"""deploy-cfn-asg-deletion-protection-blocks-delete-until-cleared."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-asg-deletion-protection-blocks-delete-until-cleared"
GROUP = "deploy"
SERVICES = ["autoscaling", "cloudformation"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})
_AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


def _wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by id every 2 s for a status in ``terminal``; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _stack_events(cf, stack_id):
    """Every DescribeStackEvents row for the stack, oldest first."""
    rows = []
    kw = {"StackName": stack_id}
    while True:
        page = cf.describe_stack_events(**kw)
        rows.extend(page["StackEvents"])
        token = page.get("NextToken")
        if not token:
            break
        kw["NextToken"] = token
    return rows[::-1]


def _resource_failure_reason(events, logical_id, status):
    """The ``ResourceStatusReason`` of ``logical_id``'s most recent row in ``status``."""
    for e in events[::-1]:
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status:
            return e.get("ResourceStatusReason")
    raise AssertionError(f"no {status!r} event found for {logical_id!r} in {events!r}")


_HANDLER_WRAPPER_RE = re.compile(
    r'^Resource handler returned message: "(?P<msg>.*)" '
    r"\(RequestToken: [0-9a-f-]{36}, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$"
)
_SDK_WRAPPER_RE = re.compile(
    r"^(?P<text>.*) \(Service: AutoScaling, Status Code: 400, "
    r"Request ID: [0-9a-f-]{36}\) \(SDK Attempt Count: \d+\)$"
)


def _asg_handler_error(reason):
    """``(HandlerErrorCode, message)`` of a resource handler failure reason.

    Request ids and the SDK attempt count vary every call, so the wrapper regexes strip them
    by shape rather than pin their value.
    """
    outer = _HANDLER_WRAPPER_RE.match(reason or "")
    assert outer, f"resource status reason had an unexpected shape: {reason!r}"
    inner = _SDK_WRAPPER_RE.match(outer["msg"])
    assert inner, f"handler message had an unexpected shape: {outer['msg']!r}"
    return outer["code"], inner["text"]


def _template(subnet_id, asg_name, deletion_protection):
    resources = {
        "LaunchTemplate": {
            "Type": "AWS::EC2::LaunchTemplate",
            "Properties": {
                "LaunchTemplateData": {"ImageId": {"Ref": "ImageId"}, "InstanceType": "t3.micro"},
            },
        },
        "ASG": {
            "Type": "AWS::AutoScaling::AutoScalingGroup",
            "Properties": {
                "AutoScalingGroupName": asg_name,
                "MinSize": "0",
                "MaxSize": "0",
                "DesiredCapacity": "0",
                "VPCZoneIdentifier": [subnet_id],
                "DeletionProtection": deletion_protection,
                "LaunchTemplate": {
                    "LaunchTemplateId": {"Ref": "LaunchTemplate"},
                    "Version": {"Fn::GetAtt": ["LaunchTemplate", "LatestVersionNumber"]},
                },
            },
        },
    }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        # The public AMI parameter resolves inside CloudFormation, not through a check call.
        "Parameters": {"ImageId": {"Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                                   "Default": _AMI_PARAMETER}},
        "Resources": resources,
    })


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation ASG's DeletionProtection updates in place to prevent-all-deletion, then
    blocks a stack delete until it is cleared, after which the same delete removes the group.
    """
    cf = ctx.client("cloudformation")
    asgc = ctx.client("autoscaling")

    subnet_id = ctx.network().subnet_ids[0]
    stack = ctx.unique_name("sim2real-cfnasgdp-")
    asg_name = ctx.unique_name("sim2real-cfnasgdp-asg-")

    def _clear_protection():
        try:
            asgc.update_auto_scaling_group(AutoScalingGroupName=asg_name, DeletionProtection="none")
        except asgc.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", "AutoScalingGroup name not found - null"):
                return
            raise

    def _delete_stack_named():
        try:
            stack_id = cf.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {stack} does not exist"):
                return
            raise
        cf.delete_stack(StackName=stack_id)
        _wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})

    ctx.on_cleanup(_delete_stack_named)
    created = cf.create_stack(
        StackName=stack, TemplateBody=_template(subnet_id, asg_name, "none"),
        Tags=[{"Key": "sim2real", "Value": stack}],
    )
    stack_id = created["StackId"]
    # Registered right after the create, so LIFO clears the setting before the delete above is
    # attempted: once the stack is DELETE_FAILED, CloudFormation refuses to UpdateStack it, so
    # clearing deletion protection on a stuck stack has to go through AutoScaling directly.
    ctx.on_cleanup(_clear_protection)

    status = _wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack_id} create ended {status!r}"

    group = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group["DeletionProtection"] == "none", (
        f"ASG {asg_name!r} reads DeletionProtection {group['DeletionProtection']!r}, expected 'none'"
    )
    created_time = group["CreatedTime"]

    # An in-place update raises the protection level without replacing the group.
    cf.update_stack(
        StackName=stack_id, TemplateBody=_template(subnet_id, asg_name, "prevent-all-deletion"),
    )
    status = _wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"protecting update on {stack_id} ended {status!r}"
    group_after = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert (group_after["DeletionProtection"], group_after["CreatedTime"]) == (
        "prevent-all-deletion", created_time
    ), (
        f"ASG {asg_name!r} reads {group_after['DeletionProtection']!r} / "
        f"{group_after['CreatedTime']!r} after the protecting update, expected "
        f"'prevent-all-deletion' on the same group"
    )

    # Deleting the stack while protected fails, and the group is left behind.
    cf.delete_stack(StackName=stack_id)
    status = _wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert status == "DELETE_FAILED", f"delete under deletion protection ended {status!r}"
    reason = _resource_failure_reason(_stack_events(cf, stack_id), "ASG", "DELETE_FAILED")
    code, message = _asg_handler_error(reason)
    assert (code, message) == (
        "InvalidRequest",
        "You cannot delete this group because its deletion protection is set to "
        "prevent-all-deletion. If you are sure that you want to delete this group, remove "
        "deletion protection for the group and try again.",
    ), f"ASG DELETE_FAILED handler error was {(code, message)!r}"

    still_there = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert [g["CreatedTime"] for g in still_there] == [created_time], (
        f"expected the same {asg_name!r} left behind by the failed delete, got {still_there!r}"
    )

    # The stack itself can no longer be updated once it is DELETE_FAILED; clearing the setting
    # that blocked the delete is only possible through AutoScaling directly.
    asgc.update_auto_scaling_group(AutoScalingGroupName=asg_name, DeletionProtection="none")
    cleared = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert (cleared["DeletionProtection"], cleared["CreatedTime"]) == ("none", created_time), (
        f"ASG {asg_name!r} reads {cleared['DeletionProtection']!r} / {cleared['CreatedTime']!r} "
        f"after clearing protection directly, expected 'none' on the same group"
    )

    # Retrying the same delete now removes it.
    cf.delete_stack(StackName=stack_id)
    status = _wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert status == "DELETE_COMPLETE", f"retried delete ended {status!r}"
    gone = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    assert gone == [], f"ASG {asg_name!r} still exists after the retried stack delete: {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
