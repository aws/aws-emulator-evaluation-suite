"""sam-layerversion-serves-function-and-outlives-stack."""

from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-layerversion-serves-function-and-outlives-stack"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "s3"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_TEMPLATE = "sam_layerversion"

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_DEADLINE_S = 600.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A SAM LayerVersion is mounted under /opt for the function that lists it, and its default
    Retain policy keeps the layer version after the stack is deleted.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-layerversion.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    fn = ctx.unique_name("sim2real-sam-layer-")
    layer = ctx.unique_name("sim2real-sam-layer-")
    bucket = ctx.unique_name("sim2real-sam-layer-")
    stack = ctx.unique_name("sim2real-sam-layer-")
    greeting = ctx.unique_name("hello-")
    body = (DEPLOYMENTS / _TEMPLATE / "template.yaml").read_text()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("python/sim2reallayer.py", f"GREETING = {greeting!r}\n")
    _make_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key="layer.zip", Body=buf.getvalue())

    # The retained layer is the check's to delete, after the stack.
    ctx.on_cleanup(lambda: _delete_layer_versions(lam, layer))
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    stack_id = _create_stack(ctx, cfn, stack, body, {
        "FunctionName": fn, "LayerName": layer, "LayerBucket": bucket, "LayerKey": "layer.zip"})

    resources = _processed(cfn, stack_id)["Resources"]
    layers = {lid: r for lid, r in resources.items() if r["Type"] == "AWS::Lambda::LayerVersion"}
    assert len(layers) == 1, f"one generated LayerVersion expected; got {sorted(layers)!r}"
    (generated,) = layers.values()
    assert generated.get("DeletionPolicy") == "Retain", (
        f"the default RetentionPolicy must become DeletionPolicy Retain; got {generated!r}")

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    layer_arn = outputs["LayerArn"]
    assert layer_arn == f"arn:aws:lambda:{ctx.region}:{ctx.account}:layer:{layer}:1", (
        f"Ref of the layer must be version 1 of {layer}; got {layer_arn!r}")
    attached = [x["Arn"] for x in lam.get_function_configuration(FunctionName=fn)["Layers"]]
    assert attached == [layer_arn], f"the function must list the layer; got {attached!r}"
    payload = _invoke(lam, fn)
    assert payload == {"greeting": greeting, "path": "/opt/python/sim2reallayer.py"}, (
        f"the function must import the module from the mounted layer; got {payload!r}")

    _delete_stack(cfn, stack_id)
    kept = lam.get_layer_version(LayerName=layer, VersionNumber=1)
    assert (kept["LayerVersionArn"], kept["CompatibleRuntimes"]) == (layer_arn, ["python3.13"]), (
        f"the retained layer version must survive the stack; got {kept!r}")
    gone, gone_msg = _error(lambda: lam.get_function(FunctionName=fn))
    assert gone == "ResourceNotFoundException", (
        f"the function, which has no DeletionPolicy, must not survive the stack; got {gone!r}")
    assert gone_msg == f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}", (
        f"expected the exact 'ResourceNotFoundException' message, got {gone_msg!r}")


def _error(fn):
    """Call fn(), which AWS must refuse; return the refusal's (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _delete_layer_versions(lam, layer: str) -> None:
    for page in lam.get_paginator("list_layer_versions").paginate(LayerName=layer):
        for version in page["LayerVersions"]:
            lam.delete_layer_version(LayerName=layer, VersionNumber=version["Version"])


def _make_bucket(ctx, s3, name: str) -> None:
    """Create the bucket with a teardown that empties and deletes it."""
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":  # the one region that takes no LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def empty_and_delete() -> None:
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=name, Key=obj["Key"])
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(empty_and_delete)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})


def _invoke(lam, fn: str) -> dict:
    """Decoded payload of a synchronous invoke that must not raise."""
    out = lam.invoke(FunctionName=fn, Payload=b"{}")
    body = out["Payload"].read().decode()
    assert "FunctionError" not in out, f"{fn} raised: {body[:300]!r}"
    return json.loads(body)


def _poll(probe, done, *, timeout_s: float, interval_s: float = 3.0, what: str = "condition"):
    """probe() until done(result); returns the result and raises at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    """The stack's next terminal status, so a wrong one is reported rather than timed out."""
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    """(logical id, reason) of every failed resource event, for a failing assert's message."""
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _processed(cfn, stack_id: str) -> dict:
    body = cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"]
    return body if isinstance(body, dict) else json.loads(body)


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete by StackId and wait for DELETE_COMPLETE; any other end raises."""
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _create_stack(ctx, cfn, name: str, body: str, params: dict) -> str:
    """Create the stack with its delete registered at once; assert CREATE_COMPLETE."""
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=body, Capabilities=_CAPS,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()],
        Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _settle(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {name} ended {status}: {_failures(cfn, stack_id)!r}"
    return stack_id


def _reap_log_group(logs, name: str, *, reads: int = 2, interval_s: float = 1.0,
                    budget_s: float = 60.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads, ``interval_s`` apart, find it
    absent; a late log flush that re-creates the group is deleted again."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while True:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
            if absent >= reads:
                return
        if time.monotonic() > deadline:
            raise AssertionError(f"log group {name} still re-appears after {budget_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
