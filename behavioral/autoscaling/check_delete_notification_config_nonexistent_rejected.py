"""delete-notification-config-nonexistent-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-notification-config-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteNotificationConfiguration for a real SNS topic never configured on the group fails,
    while the same call for a configured topic succeeds, so the rejection targets the missing
    association rather than the operation itself."""
    asg = ctx.client("autoscaling")
    sns = ctx.client("sns")
    ami_id = _get_al2_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id=ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[ctx.network().availability_zones[0]],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [ctx.network().availability_zones[0]]),
    )
    ctx.on_cleanup(lambda: _delete_asg_force(ctx, group_name))

    configured_topic_arn = _create_topic(ctx, sns, "sim2real-behav-topic-configured-")
    unconfigured_topic_arn = _create_topic(ctx, sns, "sim2real-behav-topic-unconfigured-")

    # sanity: neither topic has a notification configuration on this fresh group yet
    existing = _configs(asg, group_name)
    assert not any(n["TopicARN"] in (configured_topic_arn, unconfigured_topic_arn) for n in existing), (
        "sanity: a freshly created group already has a notification configuration for one "
        "of the topics this check just created"
    )

    # positive control: configuring a real topic and reading it back both work on this
    # group, so the account/target is otherwise healthy for this API.
    asg.put_notification_configuration(
        AutoScalingGroupName=group_name,
        TopicARN=configured_topic_arn,
        NotificationTypes=["autoscaling:TEST_NOTIFICATION"],
    )
    configs = _configs(asg, group_name)
    assert any(c["TopicARN"] == configured_topic_arn for c in configs), (
        "positive control: PutNotificationConfiguration did not become visible via "
        "DescribeNotificationConfigurations"
    )
    assert not any(c["TopicARN"] == unconfigured_topic_arn for c in configs), (
        "sanity: the never-configured topic already has a notification configuration"
    )

    # negative: the never-configured, but real, topic must be rejected.
    error = _client_error(
        lambda: asg.delete_notification_configuration(
            AutoScalingGroupName=group_name, TopicARN=unconfigured_topic_arn
        )
    )
    assert error.get("Code") == "ValidationError", (
        f"expected ValidationError for a never-configured topic, got {error!r}"
    )
    topic_account = unconfigured_topic_arn.split(":")[4]
    expected_message = (
        f"Notification Topic '{unconfigured_topic_arn}' doesn't exist for '{topic_account}'"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # terminal independent read: the negative call must not have changed any state —
    # the configured topic is still present, the unconfigured one still absent.
    configs_after = _configs(asg, group_name)
    assert any(c["TopicARN"] == configured_topic_arn for c in configs_after), (
        "the configured topic's notification configuration disappeared after the "
        "rejected delete of an unrelated topic"
    )
    assert not any(c["TopicARN"] == unconfigured_topic_arn for c in configs_after), (
        "the rejected delete nonetheless produced a notification configuration for the "
        "never-configured topic"
    )

    # positive control, second leg: the identical call against the topic that *is*
    # configured must succeed, proving the rejection above was about the missing
    # association, not a blanket refusal of DeleteNotificationConfiguration.
    asg.delete_notification_configuration(
        AutoScalingGroupName=group_name, TopicARN=configured_topic_arn
    )
    configs_final = _configs(asg, group_name)
    assert not any(c["TopicARN"] == configured_topic_arn for c in configs_final), (
        "DeleteNotificationConfiguration for the previously-configured topic did not "
        "take effect"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so accepting
    input AWS refuses is not reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_topic(ctx, sns, prefix: str) -> str:
    name = ctx.unique_name(prefix)
    topic_arn = sns.create_topic(
        Name=name,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    return topic_arn


def _configs(asg, group_name: str) -> list:
    return asg.describe_notification_configurations(AutoScalingGroupNames=[group_name])[
        "NotificationConfigurations"
    ]


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _delete_asg_force(ctx, name: str) -> None:
    asg = ctx.client("autoscaling")
    for _ in range(20):
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ScalingActivityInProgress", "ResourceContention", "ResourceInUse"):
                time.sleep(5)
                continue
            if code == "ValidationError":
                return
            raise


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
