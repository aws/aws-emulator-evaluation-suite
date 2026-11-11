"""notification-config-empty-vs-absent-field-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "notification-config-empty-vs-absent-field-preserved"
GROUP = "representation"
SERVICES = ["autoscaling"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A lifecycle hook's NotificationTargetARN: an explicit empty string clears it, while
    omitting the field on an update leaves the previously stored value untouched -- the two
    are NOT coerced to the same thing on round-trip through Put/DescribeLifecycleHooks."""
    autoscaling = ctx.client("autoscaling")
    ctx.client("sns")
    ctx.client("iam")

    asg_name = _create_asg(ctx)
    topic_arn = _create_topic(ctx)
    role_arn = _create_publish_role(ctx, topic_arn)

    hook1 = ctx.unique_name("sim2real-behav-hook1-")
    _put_hook_with_retry(
        ctx,
        LifecycleHookName=hook1,
        AutoScalingGroupName=asg_name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        NotificationTargetARN=topic_arn,
        RoleARN=role_arn,
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_lifecycle_hook(
            LifecycleHookName=hook1, AutoScalingGroupName=asg_name
        )
    )

    hooks = autoscaling.describe_lifecycle_hooks(
        AutoScalingGroupName=asg_name, LifecycleHookNames=[hook1]
    )["LifecycleHooks"]
    assert hooks[0]["NotificationTargetARN"] == topic_arn, (
        f"expected NotificationTargetARN {topic_arn!r} after initial PutLifecycleHook, "
        f"got {hooks[0]!r}"
    )

    # Explicitly setting NotificationTargetARN to "" overrides (clears) the stored ARN.
    autoscaling.put_lifecycle_hook(
        LifecycleHookName=hook1,
        AutoScalingGroupName=asg_name,
        NotificationTargetARN="",
    )
    hooks_after_clear = autoscaling.describe_lifecycle_hooks(
        AutoScalingGroupName=asg_name, LifecycleHookNames=[hook1]
    )["LifecycleHooks"]
    assert hooks_after_clear[0].get("NotificationTargetARN", "") == "", (
        "explicit empty-string NotificationTargetARN was not preserved as an override: "
        f"got {hooks_after_clear[0]!r}"
    )

    # A second hook: set the target, then update WITHOUT mentioning NotificationTargetARN at
    # all -- the previously stored value must survive untouched (absent != empty).
    hook2 = ctx.unique_name("sim2real-behav-hook2-")
    _put_hook_with_retry(
        ctx,
        LifecycleHookName=hook2,
        AutoScalingGroupName=asg_name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        NotificationTargetARN=topic_arn,
        RoleARN=role_arn,
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_lifecycle_hook(
            LifecycleHookName=hook2, AutoScalingGroupName=asg_name
        )
    )
    autoscaling.put_lifecycle_hook(
        LifecycleHookName=hook2,
        AutoScalingGroupName=asg_name,
        HeartbeatTimeout=120,
    )
    hooks2 = autoscaling.describe_lifecycle_hooks(
        AutoScalingGroupName=asg_name, LifecycleHookNames=[hook2]
    )["LifecycleHooks"]
    assert hooks2[0]["NotificationTargetARN"] == topic_arn, (
        "omitting NotificationTargetARN on an update must NOT clear the stored value: "
        f"got {hooks2[0]!r}"
    )
    assert hooks2[0]["HeartbeatTimeout"] == 120, (
        f"expected HeartbeatTimeout 120 from the same update that omitted "
        f"NotificationTargetARN, got {hooks2[0]!r}"
    )


def _create_launch_template(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    resp = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": _valid_ami(ctx), "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _valid_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _create_asg(ctx, *, min_size=0, max_size=1, desired=0):
    autoscaling = ctx.client("autoscaling")
    lt_id = _create_launch_template(ctx)
    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        AvailabilityZones=[ctx.network().availability_zones[0]],
        Tags=[{"Key": k, "Value": v, "PropagateAtLaunch": True} for k, v in _MANAGED_TAGS.items()],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [ctx.network().availability_zones[0]]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )
    return asg_name


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-"), Tags=_tags_kv()
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    return topic_arn


def _create_publish_role(ctx, topic_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "autoscaling.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-behav-publish"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sns:Publish", "Resource": topic_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _put_hook_with_retry(ctx, timeout_s: float = 60.0, **kwargs: Any) -> None:
    """PutLifecycleHook with an SNS notification target validates the RoleARN can be assumed
    (it sends a test message), so a freshly-created IAM role may not be usable yet -- poll
    until IAM's eventual-consistency window closes."""
    from botocore.exceptions import ClientError

    autoscaling = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            autoscaling.put_lifecycle_hook(**kwargs)
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(3)
    assert last_err is not None, "retry loop exited without ever calling PutLifecycleHook"
    raise last_err


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
