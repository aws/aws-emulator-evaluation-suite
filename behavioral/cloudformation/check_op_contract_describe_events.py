"""op-contract-describeEvents."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-describeEvents"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_BUCKET_TEMPLATE = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEvents groups create-stack progress events by operation for a
    real stack; calling it without ChangeSetName/OperationId/StackName is
    rejected with ValidationError (one of the three must be supplied)."""
    cfn = ctx.client("cloudformation")
    if not hasattr(cfn, "describe_events"):
        raise AssertionError("cloudformation.describe_events not available in this boto3 version")

    stack_name = ctx.unique_name("sim2real-cfn-events-")
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_BUCKET_TEMPLATE,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})

    resp = cfn.describe_events(StackName=stack_name)
    events = resp["OperationEvents"]
    assert isinstance(events, list) and len(events) > 0, f"expected a non-empty event list, got {events!r}"
    assert any(e.get("OperationType") == "CREATE_STACK" for e in events), events[:2]
    bucket_statuses = sorted(
        e.get("ResourceStatus") for e in events if e.get("LogicalResourceId") == "Bucket"
    )
    assert bucket_statuses == ["CREATE_COMPLETE", "CREATE_IN_PROGRESS", "CREATE_IN_PROGRESS"], (
        f"the Bucket's create events carry statuses {bucket_statuses!r}"
    )

    code, message = _error(lambda: cfn.describe_events())
    assert code == "ValidationError", (
        f"expected ValidationError when no ChangeSetName/OperationId/StackName given, got {code}"
    )
    assert message == "One of ChangeSetName, OperationId or StackName must be specified.", (
        f"unexpected ValidationError message {message!r}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    a target ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_for_stack_status(ctx, stack_name, terminal_statuses, timeout_s=180.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        last = resp["Stacks"][0]["StackStatus"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not reach {terminal_statuses} in {timeout_s}s (last={last})"
    )


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
