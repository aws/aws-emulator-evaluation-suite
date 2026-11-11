"""execute-change-set-twice-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-change-set-twice-rejected"
GROUP = "server-side"
SERVICES = ["cloudformation"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-executing an already-EXECUTE_COMPLETE change set is rejected, not silently re-applied."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-execcs-twice-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template(30)),
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_id))
    create_status = _wait_stack_terminal(cfn, stack_id)
    assert create_status == "CREATE_COMPLETE", f"stack creation should succeed, got {create_status}"

    change_set_name = ctx.unique_name("sim2real-cs-")
    cs = cfn.create_change_set(
        StackName=stack_id,
        ChangeSetName=change_set_name,
        ChangeSetType="UPDATE",
        TemplateBody=json.dumps(_template(45)),
    )
    change_set_id = cs["Id"]
    _wait_change_set_ready(cfn, change_set_id)

    cfn.execute_change_set(ChangeSetName=change_set_id)
    status = _wait_stack_terminal(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"first execution should succeed, got {status}"

    exec_status = cfn.describe_change_set(ChangeSetName=change_set_id)["ExecutionStatus"]
    assert exec_status == "EXECUTE_COMPLETE", exec_status

    err = _expect_error(lambda: cfn.execute_change_set(ChangeSetName=change_set_id)).response["Error"]
    # Real AWS returns the error Code without the "Exception" suffix that the
    # published shape name (InvalidChangeSetStatusException) would suggest.
    assert err["Code"] == "InvalidChangeSetStatus", (
        f"expected InvalidChangeSetStatus, got {err['Code']}"
    )
    expected_message = (
        f"ChangeSet [{change_set_id}] cannot be executed in its current execution status of "
        "[EXECUTE_COMPLETE]"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # The rejected re-execution must be a no-op, not merely a rejected request:
    # confirm via independent reads (different operation than the mutator) that
    # neither the change set's nor the stack's terminal state moved.
    post_exec_status = cfn.describe_change_set(ChangeSetName=change_set_id)["ExecutionStatus"]
    assert post_exec_status == "EXECUTE_COMPLETE", (
        f"rejected re-execution must not change change set execution status, got {post_exec_status}"
    )
    post_stack_status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert post_stack_status == "UPDATE_COMPLETE", (
        f"rejected re-execution must not disturb the stack, got {post_stack_status}"
    )


def _template(timeout: int) -> dict:
    return {"Resources": {"Queue": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": timeout}}}}


def _expect_error(fn):
    """Call fn(); return the raised ClientError. Raise if fn() succeeds unexpectedly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_change_set_ready(cfn, change_set_id: str, timeout_s: float = 120.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_change_set(ChangeSetName=change_set_id)
        status = resp["Status"]
        if status not in ("CREATE_PENDING", "CREATE_IN_PROGRESS"):
            assert status == "CREATE_COMPLETE", f"change set failed to become ready: {resp}"
            return
        time.sleep(interval_s)
    raise AssertionError(f"change set did not become ready within {timeout_s}s (last={status})")


def _wait_stack_terminal(cfn, stack_name: str, timeout_s: float = 180.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        stacks = resp.get("Stacks", [])
        if not stacks:
            return "DELETE_COMPLETE"
        status = stacks[0]["StackStatus"]
        if status in _STACK_TERMINAL:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach terminal status within {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
