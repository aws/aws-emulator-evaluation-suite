"""continue-update-rollback-wrong-state-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "continue-update-rollback-wrong-state-rejected"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ContinueUpdateRollback only applies to a stack stuck in
    UPDATE_ROLLBACK_FAILED; calling it on a healthy CREATE_COMPLETE stack is
    rejected, rather than silently no-op'd."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-continue-rb-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
            }
        ),
    )
    ctx.on_cleanup(lambda: _best_effort_delete_stack(cfn, stack_name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"),
        timeout_s=180,
        interval_s=5,
    )
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"setup: expected CREATE_COMPLETE, got {status}"

    code, message = _error(lambda: cfn.continue_update_rollback(StackName=stack_name))
    assert code == "ValidationError", f"unexpected error code: {code}"
    expected = "RollbackUpdatedStack cannot be called from current stack status"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # independent read at the destination: the rejected call must have had no effect
    # on the stack the way a real state transition (or even a no-op ack) would.
    after = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert after == "CREATE_COMPLETE", (
        f"rejected ContinueUpdateRollback must not change stack state, but status is now {after}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError raised. A call that
    succeeds raises AssertionError: the target accepted what AWS refuses."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"ContinueUpdateRollback succeeded on a stack that was never rolling back: {result!r}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() > deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last result={result}")
        time.sleep(interval_s)
        result = probe()
    return result


def _best_effort_delete_stack(cfn, stack_name: str) -> None:
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
