"""deploy-cfn-asg-notification-configuration-round-trip-update-and-removal."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-asg-notification-configuration-round-trip-update-and-removal"
GROUP = "deploy"
SERVICES = ["autoscaling", "cloudformation", "sns"]

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


def _paginate_notifications(asgc, asg_name):
    """Every item DescribeNotificationConfigurations lists for ``asg_name``, across all pages."""
    items = []
    kw = {"AutoScalingGroupNames": [asg_name]}
    while True:
        page = asgc.describe_notification_configurations(**kw)
        items.extend(page["NotificationConfigurations"])
        token = page.get("NextToken")
        if not token:
            return items
        kw["NextToken"] = token


def _template(subnet_id, asg_name, notification_types, topic_arn):
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
                **({"NotificationConfigurations": [
                    {"TopicARN": topic_arn, "NotificationTypes": notification_types}
                ]} if notification_types else {}),
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
    """A CloudFormation ASG's SNS notification configuration reads back through
    DescribeNotificationConfigurations, grows in place, and is removed by clearing the list.
    """
    cf = ctx.client("cloudformation")
    asgc = ctx.client("autoscaling")
    sns = ctx.client("sns")

    subnet_id = ctx.network().subnet_ids[0]
    stack = ctx.unique_name("sim2real-cfnasgnotif-")
    asg_name = ctx.unique_name("sim2real-cfnasgnotif-asg-")
    topic_name = ctx.unique_name("sim2real-cfnasgnotif-topic-")

    topic_arn = sns.create_topic(Name=topic_name, Tags=[{"Key": "sim2real", "Value": topic_name}])[
        "TopicArn"
    ]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    created = cf.create_stack(
        StackName=stack,
        TemplateBody=_template(subnet_id, asg_name, ["autoscaling:TEST_NOTIFICATION"], topic_arn),
        Tags=[{"Key": "sim2real", "Value": stack}],
    )
    stack_id = created["StackId"]

    status = _wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack_id} create ended {status!r}"

    configs = _paginate_notifications(asgc, asg_name)
    got = sorted((c["TopicARN"], c["NotificationType"]) for c in configs)
    assert got == [(topic_arn, "autoscaling:TEST_NOTIFICATION")], (
        f"DescribeNotificationConfigurations on {asg_name!r} reads {got!r}"
    )

    # An in-place update adds a second notification type on the same topic.
    group_before = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    cf.update_stack(
        StackName=stack_id,
        TemplateBody=_template(
            subnet_id, asg_name,
            ["autoscaling:TEST_NOTIFICATION", "autoscaling:EC2_INSTANCE_LAUNCH"], topic_arn,
        ),
    )
    status = _wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"growing update on {stack_id} ended {status!r}"

    configs_after = _paginate_notifications(asgc, asg_name)
    got_after = sorted((c["TopicARN"], c["NotificationType"]) for c in configs_after)
    assert got_after == [
        (topic_arn, "autoscaling:EC2_INSTANCE_LAUNCH"),
        (topic_arn, "autoscaling:TEST_NOTIFICATION"),
    ], f"DescribeNotificationConfigurations on {asg_name!r} reads {got_after!r} after the update"
    group_after = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group_after["CreatedTime"] == group_before["CreatedTime"], (
        f"ASG {asg_name!r} CreatedTime changed from {group_before['CreatedTime']!r} to "
        f"{group_after['CreatedTime']!r}: the notification update replaced the group"
    )

    # Clearing the list removes both configurations while the group stays up.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(subnet_id, asg_name, None, topic_arn))
    status = _wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"clearing update on {stack_id} ended {status!r}"

    configs_cleared = _paginate_notifications(asgc, asg_name)
    assert configs_cleared == [], (
        f"notification configurations still exist on {asg_name!r} after clearing: "
        f"{configs_cleared!r}"
    )
    group_cleared = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert [g["CreatedTime"] for g in group_cleared] == [group_before["CreatedTime"]], (
        f"expected the same {asg_name!r} to still exist with its notifications cleared, got "
        f"{group_cleared!r}"
    )

    _delete_stack(cf, stack_id)
    gone = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    assert gone == [], f"ASG {asg_name!r} still exists after stack delete: {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
