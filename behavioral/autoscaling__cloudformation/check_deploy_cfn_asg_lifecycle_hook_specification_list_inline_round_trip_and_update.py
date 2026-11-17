"""deploy-cfn-asg-lifecycle-hook-specification-list-inline-round-trip-and-update."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-asg-lifecycle-hook-specification-list-inline-round-trip-and-update"
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


def _delete_stack(cf, stack_id):
    """Delete by id and wait for a terminal delete status; raise unless it is DELETE_COMPLETE."""
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    status = _wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert status == "DELETE_COMPLETE", f"stack {stack_id} delete ended {status!r}"


def _template(subnet_id, asg_name, hook_spec):
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
                "LaunchTemplate": {
                    "LaunchTemplateId": {"Ref": "LaunchTemplate"},
                    "Version": {"Fn::GetAtt": ["LaunchTemplate", "LatestVersionNumber"]},
                },
                **({"LifecycleHookSpecificationList": [hook_spec]} if hook_spec else {}),
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
    """A lifecycle hook specified inline on a CloudFormation ASG reads back through
    DescribeLifecycleHooks, updates in place, and disappears when the list is cleared.
    """
    cf = ctx.client("cloudformation")
    asgc = ctx.client("autoscaling")

    subnet_id = ctx.network().subnet_ids[0]
    stack = ctx.unique_name("sim2real-cfnasghook-")
    asg_name = ctx.unique_name("sim2real-cfnasghook-asg-")
    hook_name = ctx.unique_name("sim2real-cfnasghook-hook-")

    first_spec = {
        "LifecycleHookName": hook_name,
        "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
        "HeartbeatTimeout": 60,
        "DefaultResult": "ABANDON",
    }

    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    created = cf.create_stack(
        StackName=stack, TemplateBody=_template(subnet_id, asg_name, first_spec),
        Tags=[{"Key": "sim2real", "Value": stack}],
    )
    stack_id = created["StackId"]

    status = _wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack_id} create ended {status!r}"

    hooks = asgc.describe_lifecycle_hooks(AutoScalingGroupName=asg_name)["LifecycleHooks"]
    assert [h["LifecycleHookName"] for h in hooks] == [hook_name], (
        f"DescribeLifecycleHooks on {asg_name!r} lists {hooks!r}, expected only {hook_name!r}"
    )
    got = {k: hooks[0][k] for k in ("LifecycleTransition", "HeartbeatTimeout", "DefaultResult")}
    assert got == {
        "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
        "HeartbeatTimeout": 60,
        "DefaultResult": "ABANDON",
    }, f"inline lifecycle hook {hook_name!r} reads {got!r}"

    # An in-place update changes the hook's own properties without touching the ASG itself.
    group_before = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    updated_spec = {**first_spec, "HeartbeatTimeout": 120, "DefaultResult": "CONTINUE"}
    cf.update_stack(StackName=stack_id, TemplateBody=_template(subnet_id, asg_name, updated_spec))
    status = _wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"updating update on {stack_id} ended {status!r}"

    hooks_after = asgc.describe_lifecycle_hooks(AutoScalingGroupName=asg_name)["LifecycleHooks"]
    assert [h["LifecycleHookName"] for h in hooks_after] == [hook_name], (
        f"DescribeLifecycleHooks on {asg_name!r} lists {hooks_after!r} after the update, "
        f"expected only {hook_name!r}"
    )
    got_after = {
        k: hooks_after[0][k] for k in ("LifecycleTransition", "HeartbeatTimeout", "DefaultResult")
    }
    assert got_after == {
        "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
        "HeartbeatTimeout": 120,
        "DefaultResult": "CONTINUE",
    }, f"lifecycle hook {hook_name!r} reads {got_after!r} after the update"
    group_after = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group_after["CreatedTime"] == group_before["CreatedTime"], (
        f"ASG {asg_name!r} CreatedTime changed from {group_before['CreatedTime']!r} to "
        f"{group_after['CreatedTime']!r}: the hook update replaced the group"
    )

    # Clearing the list removes the hook while the group it belongs to stays up.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(subnet_id, asg_name, None))
    status = _wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"clearing update on {stack_id} ended {status!r}"

    hooks_cleared = asgc.describe_lifecycle_hooks(
        AutoScalingGroupName=asg_name, LifecycleHookNames=[hook_name]
    )["LifecycleHooks"]
    assert hooks_cleared == [], (
        f"lifecycle hook {hook_name!r} still exists after clearing the list: {hooks_cleared!r}"
    )
    group_cleared = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert [g["CreatedTime"] for g in group_cleared] == [group_before["CreatedTime"]], (
        f"expected the same {asg_name!r} to still exist with its hook cleared, got "
        f"{group_cleared!r}"
    )

    _delete_stack(cf, stack_id)
    gone = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    assert gone == [], f"ASG {asg_name!r} still exists after stack delete: {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
