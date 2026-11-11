"""stack-rollback-on-resource-failure."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-rollback-on-resource-failure"
GROUP = 'rollback'
SERVICES = ['cloudformation']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A stack whose resource deterministically fails (WaitCondition timeout) transitions
    CREATE_IN_PROGRESS -> CREATE_FAILED -> ROLLBACK_IN_PROGRESS -> ROLLBACK_COMPLETE, in that
    order, no sooner than the WaitCondition's own configured Timeout."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cfn-rollback-")
    timeout_s = 10
    tmpl = _wait_condition_template(timeout_s=timeout_s)
    cfn.create_stack(StackName=name, TemplateBody=tmpl)
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, name))
    final = _wait_stack_status(cfn, name, timeout_s=240)
    assert final["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"expected ROLLBACK_COMPLETE after the WaitCondition timed out, got {final['StackStatus']}"
    )

    # The failure must be attributed to the WaitCondition resource, not the stack alone.
    events = cfn.describe_stack_events(StackName=name)["StackEvents"]
    failed = [
        e
        for e in events
        if e["LogicalResourceId"] == "MyWait" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert failed, "expected a CREATE_FAILED event for the timed-out WaitCondition"

    stack_events = [e for e in events if e["ResourceType"] == "AWS::CloudFormation::Stack"]
    statuses = [e["ResourceStatus"] for e in stack_events]
    assert "ROLLBACK_IN_PROGRESS" in statuses, (
        f"expected ROLLBACK_IN_PROGRESS among stack-level events, got {statuses}"
    )
    assert "CREATE_IN_PROGRESS" in statuses, (
        f"expected CREATE_IN_PROGRESS among stack-level events, got {statuses}"
    )

    # describe_stack_events is most-recent-first; Timestamp (not list position) is the true
    # order, and it also lets us prove the timeout was actually honored, not short-circuited.
    create_in_progress_ts = min(
        e["Timestamp"] for e in stack_events if e["ResourceStatus"] == "CREATE_IN_PROGRESS"
    )
    wait_failed_ts = min(e["Timestamp"] for e in failed)
    rollback_in_progress_ts = min(
        e["Timestamp"] for e in stack_events if e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS"
    )
    rollback_complete_ts = max(
        e["Timestamp"] for e in stack_events if e["ResourceStatus"] == "ROLLBACK_COMPLETE"
    )
    assert (
        create_in_progress_ts < wait_failed_ts < rollback_in_progress_ts <= rollback_complete_ts
    ), (
        "expected CREATE_IN_PROGRESS < WaitCondition CREATE_FAILED < ROLLBACK_IN_PROGRESS <= "
        f"ROLLBACK_COMPLETE, got {create_in_progress_ts}, {wait_failed_ts}, "
        f"{rollback_in_progress_ts}, {rollback_complete_ts}"
    )

    elapsed = (wait_failed_ts - create_in_progress_ts).total_seconds()
    assert elapsed >= timeout_s * 0.6, (
        f"WaitCondition CREATE_FAILED fired after only {elapsed:.1f}s; its configured Timeout "
        f"is {timeout_s}s and a real target must not fail sooner"
    )


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_condition_template(timeout_s=10) -> str:
    """A stack whose only resource is a WaitCondition that will time out after *timeout_s*
    seconds unless it is signalled — a deterministic CREATE_FAILED -> ROLLBACK_COMPLETE driver."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyHandle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
                "MyWait": {
                    "Type": "AWS::CloudFormation::WaitCondition",
                    "DependsOn": "MyHandle",
                    "Properties": {
                        "Handle": {"Ref": "MyHandle"},
                        "Timeout": str(timeout_s),
                        "Count": 1,
                    },
                },
            },
        }
    )


def _describe_stack(cfn, name):
    stacks = cfn.describe_stacks(StackName=name).get("Stacks", [])
    assert stacks, f"stack {name} not found"
    return stacks[0]


def _wait_stack_status(cfn, name, timeout_s=180, interval_s=3):
    """Poll DescribeStacks until the stack reaches any terminal status."""
    return _poll_until(
        lambda: _describe_stack(cfn, name),
        lambda stack: stack.get("StackStatus") in _TERMINAL_STACK_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"stack {name} reaching a terminal status",
    )


def _delete_stack_quiet(cfn, name):
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
