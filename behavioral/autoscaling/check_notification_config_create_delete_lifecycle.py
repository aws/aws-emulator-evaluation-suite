"""notification-config-create-delete-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "notification-config-create-delete-lifecycle"
GROUP = 'notifications'
SERVICES = ['autoscaling']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutNotificationConfiguration -> DescribeNotificationConfigurations(present) ->
    a malformed TopicARN is rejected without disturbing the existing configuration ->
    DeleteNotificationConfiguration -> DescribeNotificationConfigurations(absent)."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    sns = ctx.client("sns")

    def _image_id():
        param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        try:
            return ssm.get_parameter(Name=param)["Parameter"]["Value"]
        except Exception:
            imgs = sorted(
                ec2.describe_images(
                    Owners=["amazon"],
                    Filters=[
                        {"Name": "name", "Values": ["al2023-ami-kernel-default-x86_64*"]},
                        {"Name": "state", "Values": ["available"]},
                    ],
                ).get("Images", []),
                key=lambda i: i.get("CreationDate", ""),
            )
            if not imgs:
                raise AssertionError("no Amazon Linux 2023 AMI available in this region")
            return imgs[-1]["ImageId"]

    def _subnet_ids():
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        if not subnets:
            raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
        return [s["SubnetId"] for s in sorted(subnets, key=lambda s: s["AvailabilityZone"])[:2]]

    def _make_lt(instance_type="t3.micro"):
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": _image_id(), "InstanceType": instance_type},
        )
        ctx.on_cleanup(lambda n=lt_name: ec2.delete_launch_template(LaunchTemplateName=n))
        return lt_name

    def _make_asg(min_size=0, max_size=1, desired_capacity=0, launch_template_name=None, **kwargs):
        if launch_template_name is None:
            launch_template_name = _make_lt()
        asg_name = ctx.unique_name("sim2real-behav-as-grp-")
        params = {
            "AutoScalingGroupName": asg_name,
            "LaunchTemplate": {"LaunchTemplateName": launch_template_name, "Version": "$Latest"},
            "MinSize": min_size,
            "MaxSize": max_size,
            "DesiredCapacity": desired_capacity,
            "VPCZoneIdentifier": ",".join(_subnet_ids()),
            "HealthCheckGracePeriod": 0,
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(
            lambda n=asg_name: as_.delete_auto_scaling_group(
                AutoScalingGroupName=n, ForceDelete=True
            )
        )
        return asg_name

    def _error(fn):
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        raise AssertionError(
            f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
        )

    name = _make_asg(min_size=0, max_size=2, desired_capacity=0)
    topic_name = ctx.unique_name("sim2real-behav-topic-")
    topic_arn = sns.create_topic(
        Name=topic_name,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["TopicArn"]
    ctx.on_cleanup(lambda a=topic_arn: sns.delete_topic(TopicArn=a))

    as_.put_notification_configuration(
        AutoScalingGroupName=name,
        TopicARN=topic_arn,
        NotificationTypes=["autoscaling:TEST_NOTIFICATION"],
    )
    resp = as_.describe_notification_configurations(AutoScalingGroupNames=[name])
    configs = [c for c in resp["NotificationConfigurations"] if c["TopicARN"] == topic_arn]
    assert len(configs) == 1, f"expected exactly 1 notification configuration for {topic_arn}, saw {configs!r}"
    assert configs[0]["NotificationType"] == "autoscaling:TEST_NOTIFICATION", (
        f"expected NotificationType autoscaling:TEST_NOTIFICATION, got {configs[0]['NotificationType']!r}"
    )

    # Overly-permissive guard: a malformed TopicARN must be rejected, not silently accepted.
    code, message = _error(
        lambda: as_.put_notification_configuration(
            AutoScalingGroupName=name,
            TopicARN="not-an-arn",
            NotificationTypes=["autoscaling:TEST_NOTIFICATION"],
        )
    )
    assert code == "ValidationError", f"expected ValidationError for a malformed TopicARN, got {code!r}"
    expected = "Invalid TopicARN: not-an-arn"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the rejected call left the existing configuration untouched
    resp_after_reject = as_.describe_notification_configurations(AutoScalingGroupNames=[name])
    configs_after_reject = [
        c for c in resp_after_reject["NotificationConfigurations"] if c["TopicARN"] == topic_arn
    ]
    assert len(configs_after_reject) == 1, (
        f"rejected PutNotificationConfiguration must not alter the existing configuration, "
        f"saw {configs_after_reject!r}"
    )

    as_.delete_notification_configuration(AutoScalingGroupName=name, TopicARN=topic_arn)
    resp2 = as_.describe_notification_configurations(AutoScalingGroupNames=[name])
    assert not any(c["TopicARN"] == topic_arn for c in resp2["NotificationConfigurations"]), (
        f"notification configuration for {topic_arn} still present after DeleteNotificationConfiguration"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
