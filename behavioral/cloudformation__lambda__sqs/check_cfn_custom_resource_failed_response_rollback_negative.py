"""cfn-custom-resource-failed-response-rollback-negative."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-custom-resource-failed-response-rollback-negative"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "lambda", "sqs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"

_FAILURE_REASON = "sim2real-xsvc-custom-resource-refused"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A custom resource that signals FAILED rolls its stack back to ROLLBACK_COMPLETE with a
    CREATE_FAILED event, and the queue created before it is deleted from SQS, not only marked
    DELETE_COMPLETE; the same template with SUCCESS deploys and echoes its value."""
    sqs = ctx.client("sqs")
    cfn = ctx.client("cloudformation")
    template = (DEPLOYMENTS / "custom-resource-response-status.yaml").read_text()

    recorder_name = _xname(ctx, "crfail-recorder")
    recorder_url = sqs.create_queue(
        QueueName=recorder_name,
        Attributes={"MessageRetentionPeriod": "3600"},
        tags=_xsvc_resource_tags(),
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=recorder_url))

    # ---- negative leg: the responder PUTs Status=FAILED ----
    bad_queue_name = _xname(ctx, "crfail-inner-q")
    bad_stack = _xname(ctx, "crfail-stk")
    status = _deploy_cfn_expect_terminal(
        ctx,
        template,
        stack_name=bad_stack,
        parameters={
            "RecorderQueueUrl": recorder_url,
            "RecorderQueueName": recorder_name,
            "PartialQueueName": bad_queue_name,
            "EchoValue": "unused",
            "ResponseStatus": "FAILED",
            "FailureReason": _FAILURE_REASON,
        },
        capabilities=["CAPABILITY_IAM"],
        timeout_s=900.0,
    )
    assert status == "ROLLBACK_COMPLETE", (
        f"a custom resource that answered FAILED left the stack in {status}, expected "
        "ROLLBACK_COMPLETE (CREATE_COMPLETE here means the response Status was ignored)"
    )

    # The responder really was invoked (so the rollback is a response-driven failure, not
    # a template error), and the signal was a genuine presigned callback.
    record = _wait_for_record(ctx, recorder_url, "Create", timeout_s=180.0)
    assert record["ResponseUrlSigned"], record

    # CFN must surface the failure against the custom resource's logical id.
    events = _stack_resource_events(ctx, bad_stack)
    cr_events = [e for e in events if e["LogicalResourceId"] == "Recorded"]
    assert any(e["ResourceStatus"] == "CREATE_FAILED" for e in cr_events), (
        f"no CREATE_FAILED event for the custom resource: "
        f"{[(e['ResourceStatus'], e.get('ResourceStatusReason')) for e in cr_events]}"
    )
    reasons = [e.get("ResourceStatusReason") or "" for e in cr_events]
    assert any((_FAILURE_REASON in r) or ("FAILED" in r) for r in reasons), (
        f"custom resource failure reason never surfaced in stack events: {reasons}"
    )

    # The queue created BEFORE the custom resource must have been created and then rolled back.
    queue_events = [e for e in events if e["LogicalResourceId"] == "PartialQueue"]
    statuses = [e["ResourceStatus"] for e in queue_events]
    assert "CREATE_COMPLETE" in statuses, (
        f"PartialQueue never reached CREATE_COMPLETE, so the rollback assertion below would "
        f"be vacuous: {statuses}"
    )
    assert "DELETE_COMPLETE" in statuses, (
        f"rollback did not record a DELETE_COMPLETE for PartialQueue: {statuses}"
    )
    # ...and PHYSICALLY gone, per SQS itself (the assertion CFN's own status cannot make).
    _poll_for_client_error(
        lambda: sqs.get_queue_url(QueueName=bad_queue_name),
        {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"},
        timeout_s=120.0,
        description=f"rolled-back queue {bad_queue_name} still resolvable via SQS",
    )

    # ---- control leg: same artifact, ResponseStatus=SUCCESS ----
    good_queue_name = _xname(ctx, "crok-inner-q")
    good = _deploy_cfn(
        ctx,
        template,
        parameters={
            "RecorderQueueUrl": recorder_url,
            "RecorderQueueName": recorder_name,
            "PartialQueueName": good_queue_name,
            "EchoValue": "control",
            "ResponseStatus": "SUCCESS",
            "FailureReason": _FAILURE_REASON,
        },
        capabilities=["CAPABILITY_IAM"],
        timeout_s=900.0,
    )
    assert _outputs(good)["EchoedByCustomResource"] == "control", _outputs(good)
    attrs = sqs.get_queue_attributes(
        QueueUrl=sqs.get_queue_url(QueueName=good_queue_name)["QueueUrl"],
        AttributeNames=["QueueArn"],
    )["Attributes"]
    assert attrs["QueueArn"].endswith(good_queue_name), attrs

    # The failed stack must still be describable as ROLLBACK_COMPLETE (not silently purged).
    final_bad_status = cfn.describe_stacks(StackName=bad_stack)["Stacks"][0]["StackStatus"]
    assert final_bad_status == "ROLLBACK_COMPLETE", (
        f"rolled-back stack {bad_stack} no longer describes as ROLLBACK_COMPLETE after the "
        f"control leg ran, got {final_bad_status}"
    )


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


def _poll_for_client_error(fn, codes, *, timeout_s=120.0, interval_s=5.0, description="absence"):
    """Poll fn() until it raises ClientError with an accepted code.

    Deletion of an SQS queue is eventually consistent (up to 60s), so absence must be polled
    to a bounded deadline rather than asserted once."""
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        try:
            fn()
            last = "call succeeded"
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in codes:
                return code
            last = code
        time.sleep(interval_s)
    raise AssertionError(
        f"{description}: expected error code in {sorted(codes)} within {timeout_s}s, "
        f"last={last!r}"
    )


def _wait_for_record(ctx, queue_url, request_type: str, *, timeout_s=180.0):
    """Poll the request-log queue until a JSON record with RequestType == request_type arrives.

    Filtered rather than positional: a rollback can enqueue a Create and a Delete record and
    SQS does not guarantee the order they are received in."""
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


def _stack_resource_events(ctx, stack_name: str) -> list[dict[str, Any]]:
    """Every DescribeStackEvents page for a stack, oldest first."""
    cfn = ctx.client("cloudformation")
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs = {"StackName": stack_name}
        if token:
            kwargs["NextToken"] = token
        resp = cfn.describe_stack_events(**kwargs)
        events.extend(resp.get("StackEvents", []))
        token = resp.get("NextToken")
        if not token:
            break
    return list(reversed(events))


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown: a stack that does not go raises)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _create_stack(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=600.0
) -> str:
    """CreateStack + register delete-and-wait teardown; return the stack name (no waiting)."""
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
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
    return name


def _wait_stack_terminal(ctx, stack_name: str, *, timeout_s=600.0) -> str:
    """Poll a stack to any terminal CREATE/ROLLBACK state and return that status."""
    cfn = ctx.client("cloudformation")
    return _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {
            "CREATE_COMPLETE",
            "CREATE_FAILED",
            "ROLLBACK_COMPLETE",
            "ROLLBACK_FAILED",
            "DELETE_COMPLETE",
            "DELETE_FAILED",
        },
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {stack_name} terminal state",
    )


def _deploy_cfn_expect_terminal(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=600.0
) -> str:
    """Deploy and return the terminal status, without raising when it is not CREATE_COMPLETE:
    the caller grades the failure path."""
    name = _create_stack(
        ctx,
        template,
        stack_name=stack_name,
        parameters=parameters,
        capabilities=capabilities,
        timeout_s=timeout_s,
    )
    return _wait_stack_terminal(ctx, name, timeout_s=timeout_s)


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
