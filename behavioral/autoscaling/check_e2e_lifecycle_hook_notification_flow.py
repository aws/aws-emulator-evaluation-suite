"""e2e-lifecycle-hook-notification-flow."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-lifecycle-hook-notification-flow"
GROUP = "e2e"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A launch lifecycle hook holds a new instance in Pending:Wait; completing the
    hook is what actually lets it continue to InService, and the notification config
    that was attached alongside it is echoed back exactly."""
    autoscaling = ctx.client("autoscaling")
    sns = ctx.client("sns")

    _vpc_id, subnet_ids, sg_id = _default_vpc_subnets(ctx)
    ami = _al2_ami_id(ctx)

    lt_name = ctx.unique_name("sim2real-lt-")
    ec2 = ctx.client("ec2")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro", "SecurityGroupIds": [sg_id]},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name, LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0, MaxSize=1, DesiredCapacity=0,
        VPCZoneIdentifier=subnet_ids[0], HealthCheckType="EC2", HealthCheckGracePeriod=60,
        Tags=[{"Key": "sim2real:managed", "Value": "true", "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-topic-"), Tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    hook_name = ctx.unique_name("sim2real-hook-")
    autoscaling.put_lifecycle_hook(
        LifecycleHookName=hook_name, AutoScalingGroupName=asg_name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        HeartbeatTimeout=300, DefaultResult="ABANDON",
    )

    notification_types = [
        "autoscaling:EC2_INSTANCE_LAUNCH",
        "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
        "autoscaling:EC2_INSTANCE_TERMINATE",
        "autoscaling:EC2_INSTANCE_TERMINATE_ERROR",
    ]
    autoscaling.put_notification_configuration(
        AutoScalingGroupName=asg_name, TopicARN=topic_arn, NotificationTypes=notification_types,
    )
    configs = autoscaling.describe_notification_configurations(
        AutoScalingGroupNames=[asg_name]
    )["NotificationConfigurations"]
    assert {c["TopicARN"] for c in configs} == {topic_arn}, (
        f"expected DescribeNotificationConfigurations to echo only {topic_arn!r}, "
        f"got topics {sorted({c['TopicARN'] for c in configs})!r}"
    )
    assert {c["NotificationType"] for c in configs} == set(notification_types), (
        f"expected notification types {sorted(notification_types)!r}, "
        f"got {sorted({c['NotificationType'] for c in configs})!r}"
    )

    autoscaling.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False)

    waiting = _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )["AutoScalingGroups"][0]["Instances"],
        lambda instances: any(i["LifecycleState"] == "Pending:Wait" for i in instances),
        timeout_s=180.0, interval_s=5.0,
    )
    instance_id = next(i["InstanceId"] for i in waiting if i["LifecycleState"] == "Pending:Wait")

    # cross-check via DescribeAutoScalingInstances too
    via_instances_api = autoscaling.describe_auto_scaling_instances(InstanceIds=[instance_id])["AutoScalingInstances"]
    assert via_instances_api and via_instances_api[0]["LifecycleState"] == "Pending:Wait", (
        f"expected DescribeAutoScalingInstances to independently confirm {instance_id} is "
        f"Pending:Wait, got {via_instances_api!r}"
    )

    autoscaling.complete_lifecycle_action(
        LifecycleHookName=hook_name, AutoScalingGroupName=asg_name,
        LifecycleActionResult="CONTINUE", InstanceId=instance_id,
    )

    final = _poll_until(
        lambda: autoscaling.describe_auto_scaling_instances(InstanceIds=[instance_id])["AutoScalingInstances"],
        lambda instances: instances and instances[0]["LifecycleState"] == "InService",
        timeout_s=240.0, interval_s=5.0,
    )
    assert final[0]["LifecycleState"] == "InService", (
        f"expected {instance_id} to reach InService after CompleteLifecycleAction, "
        f"got {final[0]['LifecycleState']!r}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _al2_ami_id(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"]["Value"]


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, [s["SubnetId"] for s in subnets], sg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
