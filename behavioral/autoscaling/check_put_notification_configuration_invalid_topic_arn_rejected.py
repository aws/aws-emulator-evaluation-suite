"""put-notification-configuration-invalid-topic-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-notification-configuration-invalid-topic-arn-rejected"
GROUP = "negative-classes"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutNotificationConfiguration with a malformed (non-ARN-shaped) TopicARN is rejected before
    any notification configuration is created, while a real SNS topic ARN succeeds."""
    asg = _create_empty_group(ctx)
    autoscaling = ctx.client("autoscaling")
    sns = ctx.client("sns")

    bad_arn = "not-an-arn"
    code, message = _error(
        lambda: autoscaling.put_notification_configuration(
            AutoScalingGroupName=asg,
            TopicARN=bad_arn,
            NotificationTypes=["autoscaling:EC2_INSTANCE_LAUNCH"],
        )
    )
    assert code == "ValidationError", f"expected ValidationError for a malformed TopicARN, got {code!r}"
    expected_message = f"Invalid TopicARN: {bad_arn}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no notification configuration was created for this group
    configs = autoscaling.describe_notification_configurations(AutoScalingGroupNames=[asg])[
        "NotificationConfigurations"
    ]
    assert configs == [], f"expected no notification configurations after the rejected call, got {configs!r}"

    # positive control: a real SNS topic ARN succeeds
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    autoscaling.put_notification_configuration(
        AutoScalingGroupName=asg,
        TopicARN=topic_arn,
        NotificationTypes=["autoscaling:EC2_INSTANCE_LAUNCH"],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_notification_configuration(AutoScalingGroupName=asg, TopicARN=topic_arn)
    )
    configs_good = autoscaling.describe_notification_configurations(AutoScalingGroupNames=[asg])[
        "NotificationConfigurations"
    ]
    assert any(c["TopicARN"] == topic_arn for c in configs_good), (
        f"expected {topic_arn!r} among notification configurations, got {configs_good!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_empty_group(ctx) -> str:
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _valid_ami(ctx), "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    lt_id = lt["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[_first_az(ctx)],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [_first_az(ctx)]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )
    return asg_name


def _first_az(ctx):
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"]
    return zones[0]["ZoneName"]


def _valid_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _network_zone_subnets(ctx, zones) -> str:
    """The shared network's subnets in `zones`, comma-separated for VPCZoneIdentifier."""
    by_zone = ctx.network().subnets
    missing = [z for z in zones if z not in by_zone]
    if missing:
        raise AssertionError(f"the run's shared network has no subnet in {missing}")
    return ",".join(by_zone[z] for z in zones)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
