"""create-in-progress-status."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-in-progress-status"
GROUP = 'stack_lifecycle'
SERVICES = ['cloudformation']


_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}

def _wait_terminal(cf, name, timeout_s=180):
    """Poll DescribeStacks until the stack reaches a terminal state; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")

def _handle_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    })


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Immediately after CreateStack, status is CREATE_IN_PROGRESS."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-stk-")
    cf.create_stack(StackName=name, TemplateBody=_handle_template())
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    status = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    assert status in ("CREATE_IN_PROGRESS", "CREATE_COMPLETE"), (
        f"Expected CREATE_IN_PROGRESS or CREATE_COMPLETE, got {status}"
    )
    final = _wait_terminal(cf, name)
    assert final == "CREATE_COMPLETE", f"Expected terminal CREATE_COMPLETE, got {final}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
