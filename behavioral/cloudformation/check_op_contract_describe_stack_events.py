"""op-contract-describeStackEvents."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-describeStackEvents"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_BUCKET_TEMPLATE = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStackEvents returns a stack's events newest first, so the first is the stack-level
    CREATE_COMPLETE event; for a name that never existed it fails with ValidationError
    "Stack [<name>] does not exist"."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-stackevents-")

    cfn.create_stack(StackName=stack_name, TemplateBody=_BUCKET_TEMPLATE)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})

    resp = cfn.describe_stack_events(StackName=stack_name)
    events = resp["StackEvents"]
    assert isinstance(events, list) and len(events) > 0, f"expected a non-empty event list, got {events!r}"
    assert all(e["StackName"] == stack_name for e in events), (
        f"expected every event to belong to {stack_name}, got {[e['StackName'] for e in events]}"
    )
    assert events[0]["ResourceType"] == "AWS::CloudFormation::Stack", (
        f"expected the newest (first) event to be the stack itself, got {events[0]['ResourceType']!r}"
    )
    assert events[0]["ResourceStatus"] == "CREATE_COMPLETE", (
        f"expected the newest (first) event to be CREATE_COMPLETE, got {events[0]['ResourceStatus']!r}"
    )

    missing = ctx.unique_name("sim2real-cfn-missing-")
    code, message = _error(lambda: cfn.describe_stack_events(StackName=missing))
    assert code == "ValidationError", f"expected ValidationError for unknown stack, got {code}"
    assert message == f"Stack [{missing}] does not exist", (
        f"unexpected ValidationError message {message!r}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected success raises, so a target
    that accepts input AWS refuses fails as an acceptance rather than as an error-code mismatch."""
    from botocore.exceptions import ClientError

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


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
