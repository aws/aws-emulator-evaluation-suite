"""delete-nonexistent-stack."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-stack"
GROUP = 'errors'
SERVICES = ['cloudformation']

_TERMINAL_CREATE = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStack on a name that never existed succeeds, and DescribeStacks on it still fails with
    ValidationError "Stack with id <name> does not exist"; a real stack deleted first reports the same
    not-found answer, so a target that accepts every DeleteStack without modeling stacks fails."""
    cfn = ctx.client("cloudformation")

    # --- Positive control: a real stack's delete must also succeed, and DescribeStacks
    #     must independently confirm it is gone.
    real_name = ctx.unique_name("sim2real-behav-cfn-real-")
    queue_name = ctx.unique_name("sim2real-behav-cfn-queue-")
    cfn.create_stack(StackName=real_name, TemplateBody=_queue_template(queue_name))
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, real_name))
    created = _wait_stack_status(cfn, real_name, _TERMINAL_CREATE, timeout_s=180)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"positive control: expected the setup stack to reach CREATE_COMPLETE, "
        f"got {created['StackStatus']}"
    )

    cfn.delete_stack(StackName=real_name)
    _wait_deleted(cfn, real_name, timeout_s=180)
    gone = _expect_error(lambda: cfn.describe_stacks(StackName=real_name))
    expected_gone = ("ValidationError", f"Stack with id {real_name} does not exist")
    assert gone == expected_gone, (
        f"positive control: expected {expected_gone!r} after delete, got {gone!r}"
    )

    # --- The actual subject: DeleteStack on a name that was NEVER created must not raise.
    ghost_name = ctx.unique_name("sim2real-behav-cfn-ghost-")
    cfn.delete_stack(StackName=ghost_name)

    # If DescribeStacks now succeeds, the no-op DeleteStack silently created the stack.
    ghost = _expect_error(lambda: cfn.describe_stacks(StackName=ghost_name))
    expected_ghost = ("ValidationError", f"Stack with id {ghost_name} does not exist")
    assert ghost == expected_ghost, (
        f"DescribeStacks on the ghost name: expected {expected_ghost!r}, got {ghost!r}"
    )


def _expect_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.
    Raises when fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _delete_stack_quiet(cfn, name):
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _wait_stack_status(cfn, name, terminal_statuses, *, timeout_s=180, interval_s=3):
    """Poll DescribeStacks until the stack reaches any status in terminal_statuses."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=name).get("Stacks", [])
        assert stacks, f"stack {name} not found while waiting for a terminal status"
        last = stacks[0]
        if last.get("StackStatus") in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {name} did not reach a terminal status within {timeout_s}s; last={last!r}"
    )


def _wait_deleted(cfn, name, timeout_s=180):
    """Wait until the stack reaches DELETE_COMPLETE or vanishes from DescribeStacks."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED":
                raise AssertionError(f"stack {name} reached DELETE_FAILED")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"stack {name} not deleted within {timeout_s}s")


def _queue_template(queue_name):
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name}}
            },
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
