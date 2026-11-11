"""cfn-deploy-sfn-lambda-s3-stack-positive."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sfn-lambda-s3-stack-positive"

GROUP = "deployment-order"

SERVICES = ["lambda", "s3", "stepfunctions"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


def _empty_bucket(ctx, bucket_name):
    """Delete every object (and version) in a bucket so teardown can remove it.

    CloudFormation cannot delete a non-empty S3 bucket, so a stack whose bucket
    a check populated ends in DELETE_FAILED and leaks the bucket AND the stack's
    other resources. The harness deletes stacks BEFORE tracked undos, so empty
    the bucket here (after the assertions) to let the stack teardown fully succeed.
    """
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(
            Bucket=bucket_name
        ):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                s3.delete_objects(Bucket=bucket_name, Delete={"Objects": targets})
    except Exception:
        pass
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket_name):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                s3.delete_objects(Bucket=bucket_name, Delete={"Objects": keys})
    except Exception:
        pass


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Deploy full three-service stack via CloudFormation and verify wiring."""
    template_path = DEPLOYMENTS / "sfn-lambda-s3-stack.yaml"
    assert template_path.is_file(), (
        f"deployment artifact missing on disk: {template_path}"
    )
    template = template_path.read_text()
    result = _deploy_cfn(ctx, template)
    outputs = result["outputs"]
    assert "BucketName" in outputs, "Missing BucketName output"
    assert "FunctionArn" in outputs, "Missing FunctionArn output"
    assert "StateMachineArn" in outputs, "Missing StateMachineArn output"

    bucket_name = outputs["BucketName"]
    function_name = outputs["FunctionName"]
    state_machine_arn = outputs["StateMachineArn"]

    # Invoke Lambda and verify S3 write
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name, Payload=json.dumps({"test": "cfn-deploy"}).encode()
    )
    payload = json.loads(resp["Payload"].read())
    assert payload.get("status") == "ok", f"Lambda did not return ok: {payload}"
    s3 = ctx.client("s3")
    obj = s3.get_object(Bucket=bucket_name, Key="events/invocation.json")
    body = json.loads(obj["Body"].read())
    assert body.get("test") == "cfn-deploy", f"S3 object content mismatch: {body}"

    # Start SFN execution and poll SUCCEEDED
    sfn = ctx.client("stepfunctions")
    exec_resp = sfn.start_execution(
        stateMachineArn=state_machine_arn, input=json.dumps({"test": "sfn-start"})
    )
    exec_arn = exec_resp["executionArn"]

    def check_exec():
        return sfn.describe_execution(executionArn=exec_arn)["status"]

    status = _poll_until(
        check_exec, lambda s: s in ("SUCCEEDED", "FAILED"), timeout_s=90, interval_s=3
    )
    assert status == "SUCCEEDED", f"SFN execution did not SUCCEED: {status}"

    # Lambda wrote an object; empty the bucket so the CFN stack teardown (which
    # runs before tracked undos and cannot delete a non-empty bucket) fully cleans.
    _empty_bucket(ctx, bucket_name)


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
