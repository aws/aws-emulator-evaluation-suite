"""cfn-custom-resource-create-delete-lifecycle-signals."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-custom-resource-create-delete-lifecycle-signals"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "lambda", "sqs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CFN custom resource receives a Create AND a Delete request on a presigned ResponseURL,
    and its response Data is readable through Fn::GetAtt: CloudFormation must invoke the
    customer's Lambda and wait for its callback, not treat the resource as an inert record.
    """
    sqs = ctx.client("sqs")
    cfn = ctx.client("cloudformation")

    recorder_name = _xname(ctx, "cr-recorder")
    recorder_url = sqs.create_queue(
        QueueName=recorder_name,
        Attributes={"MessageRetentionPeriod": "3600"},
        tags=_xsvc_resource_tags(),
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=recorder_url))

    partial_name = _xname(ctx, "cr-inner-q")
    echo = _xname(ctx, "echo")
    template = (DEPLOYMENTS / "custom-resource-response-status.yaml").read_text()
    result = _deploy_cfn(
        ctx,
        template,
        parameters={
            "RecorderQueueUrl": recorder_url,
            "RecorderQueueName": recorder_name,
            "PartialQueueName": partial_name,
            "EchoValue": echo,
            "ResponseStatus": "SUCCESS",
        },
        capabilities=["CAPABILITY_IAM"],
        timeout_s=900.0,
    )
    outputs = _outputs(result)
    stack_name = result["stack_name"]

    # 1. CFN parsed the Lambda's response body and published Data.Echo under Fn::GetAtt.
    assert outputs["EchoedByCustomResource"] == echo, (
        f"Fn::GetAtt on the custom resource returned "
        f"{outputs['EchoedByCustomResource']!r}, expected the echoed {echo!r}"
    )

    # 2. Ref of a custom resource is the PhysicalResourceId its Create response minted.
    physical_id = outputs["CustomResourcePhysicalId"]
    assert physical_id.startswith("sim2real-xsvc-cr-"), (
        f"Ref of the custom resource returned {physical_id!r}, expected the "
        "responder-minted physical id (CFN must adopt the id from the response body)"
    )

    # 3. The responder really ran, with a Create request on a presigned ResponseURL.
    create_record = _wait_for_record(ctx, recorder_url, "Create", timeout_s=180.0)
    assert create_record["Echo"] == echo, create_record
    assert create_record["PhysicalResourceId"] == physical_id, (
        f"Create record physical id {create_record['PhysicalResourceId']!r} != stack Ref "
        f"{physical_id!r}"
    )
    assert create_record["ResponseUrlSigned"], (
        "ResponseURL handed to the custom resource carried no SigV4/SigV2 signature: "
        f"{create_record}"
    )

    # 4. Delete the stack in-check: the SAME Lambda must be re-invoked with
    #    RequestType=Delete and the SAME physical id CFN learned at Create time.
    _delete_stack_and_wait(ctx, stack_name, timeout_s=900.0)
    delete_record = _wait_for_record(ctx, recorder_url, "Delete", timeout_s=180.0)
    assert delete_record["PhysicalResourceId"] == physical_id, (
        f"Delete request carried physical id {delete_record['PhysicalResourceId']!r}, "
        f"expected the Create-time id {physical_id!r}"
    )
    assert delete_record["ResponseUrlSigned"], delete_record

    # 5. Teardown really removed the stack (not just flipped a status field).
    _expect_client_error(
        lambda: cfn.describe_stacks(StackName=stack_name),
        {"ValidationError"},
        f"describe_stacks after delete of {stack_name}",
        f"Stack with id {stack_name} does not exist",
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _outputs(result: dict) -> dict:
    """Deployment results may nest outputs under 'outputs' or expose them flat."""
    return result.get("outputs", result)


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


def _expect_client_error(fn, codes, description, message):
    """Require fn() to raise ClientError with an Error.Code in codes and exactly `message`;
    return the code."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        assert code in codes, (
            f"{description}: expected error code in {sorted(codes)}, got {code!r} ({exc})"
        )
        got = exc.response.get("Error", {}).get("Message")
        assert got == message, f"{description}: message {got!r} != {message!r}"
        return code
    raise AssertionError(f"{description}: call unexpectedly succeeded")


def _wait_for_record(ctx, queue_url, request_type: str, *, timeout_s=180.0):
    """Poll the request-log queue until a JSON record with RequestType == request_type arrives.

    Filtered rather than positional: SQS does not guarantee the order records are received in."""
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(5, remaining),
        )
        for msg in resp.get("Messages", []):
            record = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if record.get("RequestType") == request_type:
                return record
            seen.append(record)
    raise AssertionError(
        f"no {request_type} lifecycle record within {timeout_s}s (saw {seen})"
    )


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE; a stack holding a Lambda, an IAM
    role and a custom resource can take 600 s or more to delete."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as err:
            if "does not exist" in str(err):
                return "GONE"
            raise

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
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
    timeout_s=600.0,
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
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
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
