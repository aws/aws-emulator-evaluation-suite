"""rollback-cancel-continue-flow."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rollback-cancel-continue-flow"
GROUP = 'rollback'
SERVICES = ['cloudformation']


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

def _wait_stack_status(cf, name, targets, timeout_s=180, interval_s=3):
    """Poll DescribeStacks until StackStatus is in targets; return the stack dict."""
    target = {targets} if isinstance(targets, str) else set(targets)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=name)["Stacks"][0]
        if last.get("StackStatus") in target:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {name} did not reach {target} (last={last.get('StackStatus') if last else None!r})"
    )

def _topic_template():
    return json.dumps({
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
        "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
    })

def _wait_condition_template(timeout_seconds=240):
    return json.dumps({
        "Resources": {
            "WaitHandle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Waiter": {
                "Type": "AWS::CloudFormation::WaitCondition",
                "Properties": {
                    "Handle": {"Ref": "WaitHandle"},
                    "Timeout": str(timeout_seconds),
                    "Count": "1",
                },
            },
        }
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelUpdateStack/RollbackStack/ContinueUpdateRollback are gated by current status
    and return the stack to a stable terminal state when applicable."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-rollback-")
    stack_id = cf.create_stack(
        StackName=name,
        TemplateBody=_topic_template(),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cf, stack_id))
    _wait_stack_status(cf, name, {"CREATE_COMPLETE"})

    # No update in flight -> rejected.
    code_noop, message_noop = _error(lambda: cf.cancel_update_stack(StackName=name))
    assert code_noop == "ValidationError", code_noop
    expected = "CancelUpdateStack cannot be called from current stack status"
    assert message_noop == expected, f"expected message {expected!r}, got {message_noop!r}"
    unaffected_noop = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    assert unaffected_noop == "CREATE_COMPLETE", (
        f"rejected CancelUpdateStack must not change stack state, got {unaffected_noop!r}"
    )

    # Genuinely in-flight update -> CancelUpdateStack succeeds and rolls back.
    cf.update_stack(StackName=name, TemplateBody=_wait_condition_template(300))
    _wait_stack_status(cf, name, {"UPDATE_IN_PROGRESS"}, timeout_s=60, interval_s=2)
    cf.cancel_update_stack(StackName=name)
    cancelled = _wait_stack_status(
        cf, name, {"UPDATE_ROLLBACK_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_FAILED"}, timeout_s=180
    )
    assert cancelled["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", cancelled

    # RollbackStack on a stable, non-failed stack is rejected.
    code_stable, message_stable = _error(lambda: cf.rollback_stack(StackName=name))
    assert code_stable == "ValidationError", code_stable
    expected = "RollbackStack can only be called on any of the [UPDATE_FAILED, CREATE_FAILED] statuses."
    assert message_stable == expected, f"expected message {expected!r}, got {message_stable!r}"
    unaffected_stable = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    assert unaffected_stable == "UPDATE_ROLLBACK_COMPLETE", (
        f"rejected RollbackStack must not change stack state, got {unaffected_stable!r}"
    )

    # RollbackStack on a DisableRollback stack that failed to create.
    fail_name = ctx.unique_name("sim2real-behav-rollback-fail-")
    fail_id = cf.create_stack(
        StackName=fail_name,
        TemplateBody=_wait_condition_template(10),
        DisableRollback=True,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cf, fail_id))
    failed = _wait_stack_status(cf, fail_name, {"CREATE_FAILED"}, timeout_s=120)
    assert failed["StackStatus"] == "CREATE_FAILED", failed

    cf.rollback_stack(StackName=fail_name)
    rolled_back = _wait_stack_status(
        cf, fail_name, {"ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}, timeout_s=180
    )
    assert rolled_back["StackStatus"] == "ROLLBACK_COMPLETE", rolled_back

    # A catalog-level read, independent of both the mutating call and the direct
    # DescribeStacks poll above.
    listed = [s for page in cf.get_paginator("list_stacks").paginate(StackStatusFilter=["ROLLBACK_COMPLETE"])
              for s in page["StackSummaries"]]
    assert any(s["StackName"] == fail_name for s in listed), (
        f"{fail_name} not visible via ListStacks(StackStatusFilter=[ROLLBACK_COMPLETE]): {listed}"
    )

    # ContinueUpdateRollback only makes sense stuck in UPDATE_ROLLBACK_FAILED.
    code_bad_state, message_bad_state = _error(lambda: cf.continue_update_rollback(StackName=name))
    assert code_bad_state == "ValidationError", code_bad_state
    expected = "RollbackUpdatedStack cannot be called from current stack status"
    assert message_bad_state == expected, f"expected message {expected!r}, got {message_bad_state!r}"

    # Independent read at the destination: the rejected call must have had no effect.
    unaffected_bad_state = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    assert unaffected_bad_state == "UPDATE_ROLLBACK_COMPLETE", (
        f"rejected ContinueUpdateRollback must not change stack state, got {unaffected_bad_state!r}"
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
