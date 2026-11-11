"""cfn-lambda-layer-version-reads-back-through-lambda-then-not-found-after-delete."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-layer-version-reads-back-through-lambda-then-not-found-after-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_DEADLINE_S = 300.0


def _error(fn):
    """Call fn(), which AWS must refuse; return (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _poll(probe, done, *, timeout_s: float, interval_s: float = 2.0, what: str = "condition"):
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
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _teardown_stack(cfn, stack_id: str) -> None:
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-created AWS::Lambda::LayerVersion reads back its own properties and
    GetAtt ARN through Lambda's API, and the stack delete removes it, read as a Lambda not-found.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-layerversion.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-cfn-lv-")
    layer = ctx.unique_name("sim2real-cfn-lv-")
    stack = ctx.unique_name("sim2real-cfn-lv-")
    description = ctx.unique_name("sim2real-layer-desc-")

    bucket_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        bucket_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**bucket_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("python/sim2real_marker.py", "MARKER = 1\n")
    s3.put_object(Bucket=bucket, Key="layer.zip", Body=buf.getvalue())

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Layer": {
                "Type": "AWS::Lambda::LayerVersion",
                "Properties": {
                    "LayerName": layer,
                    "Description": description,
                    "CompatibleRuntimes": ["python3.13"],
                    "Content": {"S3Bucket": bucket, "S3Key": "layer.zip"},
                },
            },
        },
        "Outputs": {
            "LayerArnOut": {"Value": {"Fn::GetAtt": ["Layer", "LayerVersionArn"]}},
        },
    }

    stack_id = cfn.create_stack(
        StackName=stack, TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    status = _settle(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack} ended {status}: {_failures(cfn, stack_id)!r}"

    physical_id = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Layer")[
        "StackResourceDetail"]["PhysicalResourceId"]
    assert physical_id == f"arn:aws:lambda:{ctx.region}:{ctx.account}:layer:{layer}:1", (
        f"LayerVersion physical id is {physical_id!r}")

    getatt_arn = {o["OutputKey"]: o["OutputValue"]
                  for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}["LayerArnOut"]
    assert getatt_arn == physical_id, (
        f"Fn::GetAtt LayerVersionArn {getatt_arn!r} does not match the physical id {physical_id!r}")

    read_back = lam.get_layer_version_by_arn(Arn=physical_id)
    assert read_back["LayerVersionArn"] == physical_id, (
        f"GetLayerVersionByArn returned ARN {read_back['LayerVersionArn']!r}, expected {physical_id!r}")
    assert read_back["Description"] == description, (
        f"the layer's Description is {read_back['Description']!r}, expected {description!r}")
    assert read_back["CompatibleRuntimes"] == ["python3.13"], (
        f"CompatibleRuntimes read back as {read_back['CompatibleRuntimes']!r}, expected ['python3.13']")

    _teardown_stack(cfn, stack_id)
    code, message = _error(lambda: lam.get_layer_version_by_arn(Arn=physical_id))
    assert code == "ResourceNotFoundException", (
        f"reading the deleted layer version returned {code!r}, expected ResourceNotFoundException")
    expected_message = "The resource you requested does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
