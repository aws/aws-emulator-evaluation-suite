"""update-rollback-restores-pre-update-state."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-rollback-restores-pre-update-state"
GROUP = 'rollback'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}


def _describe(cf, name):
    """DescribeStacks for one stack, or None when it no longer exists."""
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError:
        return None


def _wait_terminal(cf, name, *, timeout_s=600, interval_s=5):
    """Poll DescribeStacks until the stack reaches a terminal state; return the stack."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        stack = _describe(cf, name)
        last = None if stack is None else stack["StackStatus"]
        if stack is not None and last in _TERMINAL_STATES:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})"
            )
        time.sleep(interval_s)


def _template(param_name, value, *, with_failing_gate=False):
    resources = {
        "Param": {
            "Type": "AWS::SSM::Parameter",
            "Properties": {"Name": param_name, "Type": "String", "Value": value},
        },
    }
    if with_failing_gate:
        # A WaitCondition that is never signalled fails after Timeout seconds.
        # DependsOn forces the Param modification to be applied FIRST, so the
        # rollback has something real to undo.
        resources["GateHandle"] = {"Type": "AWS::CloudFormation::WaitConditionHandle"}
        resources["Gate"] = {
            "Type": "AWS::CloudFormation::WaitCondition",
            "DependsOn": "Param",
            "Properties": {"Handle": {"Ref": "GateHandle"}, "Timeout": "60", "Count": 1},
        }
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


# timing:real-time — workflow: 60 s https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-waitcondition.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A mid-update failure ends UPDATE_ROLLBACK_COMPLETE, restores the pre-update value and drops
    the added resource, and a later valid update still succeeds.
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    stack = ctx.unique_name("sim2real-behav-updroll-")
    param_name = "/" + ctx.unique_name("sim2real-behav-updroll-p-")

    cf.create_stack(StackName=stack, TemplateBody=_template(param_name, "v1"))
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack))
    created = _wait_terminal(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"setup stack must reach CREATE_COMPLETE, got {created['StackStatus']!r}: "
        f"{created.get('StackStatusReason')!r}"
    )
    assert ssm.get_parameter(Name=param_name)["Parameter"]["Value"] == "v1", (
        "setup did not write the pre-update value"
    )

    # Break exactly one thing: the update changes Param to v2 AND adds a gate
    # that is guaranteed to time out after Param has already been modified.
    cf.update_stack(StackName=stack, TemplateBody=_template(param_name, "v2", with_failing_gate=True))
    rolled = _wait_terminal(cf, stack)
    assert rolled["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"a mid-update failure must terminate in UPDATE_ROLLBACK_COMPLETE, got "
        f"{rolled['StackStatus']!r}: {rolled.get('StackStatusReason')!r}"
    )

    # The already-applied half of the update must be undone.
    reverted = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert reverted == "v1", (
        f"UPDATE_ROLLBACK must restore the pre-update property value 'v1', found {reverted!r}"
    )

    # The resource introduced by the failed update must not survive the rollback.
    logical_ids = {
        r["LogicalResourceId"]
        for r in cf.list_stack_resources(StackName=stack)["StackResourceSummaries"]
    }
    assert "Gate" not in logical_ids, (
        f"the failed update's WaitCondition must be removed by the rollback, got {sorted(logical_ids)}"
    )
    assert "Param" in logical_ids, sorted(logical_ids)

    # The rollback must be visible in the event stream, not just in the status.
    statuses = [
        e.get("ResourceStatus")
        for e in cf.describe_stack_events(StackName=stack)["StackEvents"]
    ]
    assert "UPDATE_ROLLBACK_IN_PROGRESS" in statuses, (
        f"expected an UPDATE_ROLLBACK_IN_PROGRESS stack event, got {statuses}"
    )

    # Control: the stack is not wedged -- a valid update still completes.
    cf.update_stack(StackName=stack, TemplateBody=_template(param_name, "v3"))
    updated = _wait_terminal(cf, stack)
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"a rolled-back stack must accept a subsequent valid update, got "
        f"{updated['StackStatus']!r}: {updated.get('StackStatusReason')!r}"
    )
    final_value = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert final_value == "v3", (
        f"the post-rollback update must still apply, expected 'v3', found {final_value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
