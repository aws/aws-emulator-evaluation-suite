"""put-notification-configuration-topic-limit-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-notification-configuration-topic-limit-exceeded-rejected"
GROUP = "state-machine"
SERVICES = ["autoscaling", "sns"]

_TOPIC_LIMIT = 10


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutNotificationConfiguration is rejected with LimitExceeded once an Auto Scaling group
    already has the maximum of 10 distinct SNS topics configured for notifications, and freeing
    one slot lets a new topic succeed (positive control)."""
    autoscaling = ctx.client("autoscaling")
    sns = ctx.client("sns")

    notification_type = _notification_type(ctx)

    subnet_ids = _default_subnet_ids(ctx, count=1)
    group = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=group,
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=",".join(subnet_ids),
        LaunchTemplate={"LaunchTemplateId": _create_launch_template(ctx)},
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=group, ForceDelete=True)
    )

    topic_arns = [_create_topic(ctx, i) for i in range(_TOPIC_LIMIT)]
    for arn in topic_arns:
        autoscaling.put_notification_configuration(
            AutoScalingGroupName=group, TopicARN=arn, NotificationTypes=[notification_type]
        )

    existing = _list_topic_arns(ctx, group)
    assert existing == set(topic_arns), f"expected the {_TOPIC_LIMIT} configured topics, got {sorted(existing)}"

    overflow_arn = _create_topic(ctx, "overflow")
    code, message = _error(
        lambda: autoscaling.put_notification_configuration(
            AutoScalingGroupName=group, TopicARN=overflow_arn, NotificationTypes=[notification_type]
        )
    )
    assert code == "LimitExceeded", f"expected LimitExceeded past the per-group topic cap, got {code}"
    expected_message = f"Your AutoScaling Group:{group} can't have more than {_TOPIC_LIMIT} topics"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_reject = _list_topic_arns(ctx, group)
    assert after_reject == set(topic_arns), (
        f"topic set must stay at the {_TOPIC_LIMIT} configured topics after the rejected "
        f"PutNotificationConfiguration, got {sorted(after_reject)}"
    )

    # Positive control: freeing one slot lets a new topic succeed.
    autoscaling.delete_notification_configuration(AutoScalingGroupName=group, TopicARN=topic_arns[0])
    autoscaling.put_notification_configuration(
        AutoScalingGroupName=group, TopicARN=overflow_arn, NotificationTypes=[notification_type]
    )
    final = _list_topic_arns(ctx, group)
    expected_final = set(topic_arns[1:]) | {overflow_arn}
    assert final == expected_final, (
        f"expected {overflow_arn} to succeed once a slot was freed, got topics {sorted(final)}"
    )


from botocore.exceptions import ClientError


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _notification_type(ctx) -> str:
    """The AutoScalingNotificationTypes value reserved for exercising notification wiring."""
    autoscaling = ctx.client("autoscaling")
    types = autoscaling.describe_auto_scaling_notification_types()["AutoScalingNotificationTypes"]
    wanted = "autoscaling:TEST_NOTIFICATION"
    assert wanted in types, f"expected {wanted!r} among the notification types, got {types!r}"
    return wanted


def _create_topic(ctx, suffix) -> str:
    sns = ctx.client("sns")
    name = ctx.unique_name(f"sim2real-behav-topic-{suffix}-")
    arn = sns.create_topic(Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _list_topic_arns(ctx, group: str) -> set:
    autoscaling = ctx.client("autoscaling")
    paginator = autoscaling.get_paginator("describe_notification_configurations")
    return {
        c["TopicARN"]
        for page in paginator.paginate(AutoScalingGroupNames=[group])
        for c in page["NotificationConfigurations"]
    }


def _default_subnet_ids(ctx, count: int = 1) -> list[str]:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no shared network VPC subnets available in this account/region")
    return [s["SubnetId"] for s in subnets[:count]]


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _create_launch_template(ctx, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)
    name = ctx.unique_name("sim2real-behav-lt-")
    resp = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
