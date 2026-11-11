"""delete-stack-while-create-in-progress."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-stack-while-create-in-progress"
GROUP = 'state-machine'
SERVICES = ['cloudformation']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DeleteStack issued while the stack is still CREATE_IN_PROGRESS (blocked on a
    WaitCondition) aborts the create and drives the stack to DELETE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cfn-delinflight-")
    tmpl = _wait_condition_template(timeout_s=600)
    stack_id = cfn.create_stack(StackName=name, TemplateBody=tmpl)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, name))

    # The WaitCondition is not addressable until CloudFormation starts creating it
    # (DescribeStackResource raises ValidationError before that), so poll the
    # resource *list*, which only contains resources that already exist.
    def pending_wait_condition():
        summaries = cfn.list_stack_resources(StackName=name)["StackResourceSummaries"]
        return [
            s
            for s in summaries
            if s["LogicalResourceId"] == "MyWait"
            and s["ResourceStatus"] == "CREATE_IN_PROGRESS"
        ]

    _poll_until(
        pending_wait_condition,
        lambda found: bool(found),
        timeout_s=90,
        interval_s=3,
        description="WaitCondition entering CREATE_IN_PROGRESS",
    )
    in_progress = _describe_stack(cfn, name)
    assert in_progress["StackStatus"] == "CREATE_IN_PROGRESS", in_progress["StackStatus"]

    cfn.delete_stack(StackName=name)
    final = _wait_stack_status(cfn, stack_id, timeout_s=150)
    assert final["StackStatus"] == "DELETE_COMPLETE", final["StackStatus"]


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
    """A stack whose only resource is a WaitCondition that blocks until signalled/timed out."""
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
