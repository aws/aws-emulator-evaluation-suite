"""alarm-action-executes-asg-scaling-policy."""

from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "alarm-action-executes-asg-scaling-policy"

GROUP = "alerting"

SERVICES = ["autoscaling", "cloudwatch", "ec2"]

_NAMESPACE = "sim2real/autoscaling"
_METRIC = "ScaleOutSignal"
_THRESHOLD = 70.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A CloudWatch alarm whose action is an Auto Scaling policy ARN sets the group's DesiredCapacity
    to the policy's exact capacity on ALARM, leaving MinSize/MaxSize unchanged.
    """
    as_ = ctx.client("autoscaling")
    cw = ctx.client("cloudwatch")

    asg = _make_empty_asg(ctx)
    # Suspend only Launch so capacity changes apply but no instance is provisioned;
    # AlarmNotification stays enabled because it is the process under test.
    as_.suspend_processes(AutoScalingGroupName=asg, ScalingProcesses=["Launch"])

    baseline = _describe_asg(as_, asg)
    assert baseline["DesiredCapacity"] == 0, (
        f"the group must start empty so the capacity change is attributable to the alarm, got "
        f"DesiredCapacity={baseline['DesiredCapacity']}"
    )

    policy_name = _xname(ctx, "policy")
    policy_arn = as_.put_scaling_policy(
        AutoScalingGroupName=asg,
        PolicyName=policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ExactCapacity",
        ScalingAdjustment=2,
        Cooldown=0,
    )["PolicyARN"]
    ctx.on_cleanup(
        lambda: ctx.client("autoscaling").delete_policy(
            AutoScalingGroupName=asg, PolicyName=policy_name
        )
    )
    assert policy_arn.startswith("arn:"), policy_arn

    alarm = _put_asg_alarm(ctx, policy_arn, asg, actions_enabled=True)

    # A real breach of a metric this check owns, not SetAlarmState: Auto Scaling declines
    # scaling actions arising from SetAlarmState.
    state = _poll_until(
        lambda: _push_then_state(cw, asg, alarm, _THRESHOLD * 2),
        lambda st: st == "ALARM",
        timeout_s=600,
        interval_s=20.0,
        description=f"the breaching datapoint drove alarm {alarm} into ALARM",
    )
    assert state == "ALARM", state

    group = _poll_until(
        lambda: _describe_asg(as_, asg),
        lambda g: g["DesiredCapacity"] == 2,
        timeout_s=300,
        interval_s=10.0,
        description=(
            f"alarm {alarm} executes scaling policy {policy_name} and raises "
            f"{asg} DesiredCapacity to 2"
        ),
    )
    assert group["DesiredCapacity"] == 2, (
        f"the alarm action must be executed as a scaling policy, not merely accepted; "
        f"{asg} DesiredCapacity is {group['DesiredCapacity']}, expected 2"
    )
    # A capacity change must not silently rewrite the group's bounds.
    assert group["MinSize"] == 0, (
        f"executing a scaling policy must not change MinSize, got {group['MinSize']}"
    )
    assert group["MaxSize"] == 4, (
        f"executing a scaling policy must not change MaxSize, got {group['MaxSize']}"
    )
    # With Launch suspended the group should stay empty; provisioning is not under test.
    instances = group.get("Instances", [])
    assert len(instances) <= 2, (
        f"the group must never exceed the capacity the policy set; found {len(instances)} instances"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _describe_asg(as_, name: str) -> dict[str, Any]:
    groups = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name])[
        "AutoScalingGroups"
    ]
    assert groups, f"auto scaling group {name} not found"
    return groups[0]


def _image_id(ctx) -> str:
    """Newest Amazon Linux 2023 AMI, read from EC2 (SSM is outside SERVICES).

    The filter matches real AMI names; the SSM alias name matches no image in DescribeImages.
    """
    ec2 = ctx.client("ec2")
    images = sorted(
        ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-2*-kernel-*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
            ],
        ).get("Images", []),
        key=lambda i: i.get("CreationDate", ""),
    )
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI available in this region")
    return images[-1]["ImageId"]


def _subnet_ids(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    return [
        s["SubnetId"] for s in sorted(subnets, key=lambda s: s["AvailabilityZone"])[:2]
    ]


def _make_launch_template(ctx) -> str:
    """A launch template that tags instances and volumes at creation."""
    ec2 = ctx.client("ec2")
    name = _xname(ctx, "lt")
    tag_set = _xsvc_tags_kv()
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": _image_id(ctx),
            "InstanceType": "t3.micro",
            "TagSpecifications": [
                {"ResourceType": "instance", "Tags": tag_set},
                {"ResourceType": "volume", "Tags": tag_set},
            ],
        },
    )
    ctx.on_cleanup(
        lambda: ctx.client("ec2").delete_launch_template(LaunchTemplateName=name)
    )
    return name


def _make_empty_asg(ctx) -> str:
    """An ASG with MinSize=0/DesiredCapacity=0 -- zero instances, zero cost, room to scale to 4."""
    as_ = ctx.client("autoscaling")
    lt_name = _make_launch_template(ctx)
    name = _xname(ctx, "asg")
    as_.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=4,
        DesiredCapacity=0,
        VPCZoneIdentifier=",".join(_subnet_ids(ctx)),
        HealthCheckGracePeriod=0,
        Tags=[
            {"Key": k, "Value": v, "PropagateAtLaunch": True}
            for k, v in _xsvc_resource_tags().items()
        ],
    )
    # Cleanups run in reverse: this delete runs last.
    ctx.on_cleanup(
        lambda: ctx.client("autoscaling").delete_auto_scaling_group(
            AutoScalingGroupName=name, ForceDelete=True
        )
    )
    # Runs first: wind capacity to zero so no instance survives a partial teardown.
    ctx.on_cleanup(
        lambda: ctx.client("autoscaling").update_auto_scaling_group(
            AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0
        )
    )
    return name


def _put_asg_alarm(
    ctx, policy_arn: str, asg_name: str, *, actions_enabled: bool
) -> str:
    """A metric alarm whose ONLY action is the scaling policy ARN."""
    cw = ctx.client("cloudwatch")
    name = _xname(ctx, "alarm")
    cw.put_metric_alarm(
        AlarmName=name,
        MetricName=_METRIC,
        Namespace=_NAMESPACE,
        Dimensions=[{"Name": "AutoScalingGroupName", "Value": asg_name}],
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        ActionsEnabled=actions_enabled,
        AlarmActions=[policy_arn],
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[name]))
    return name


def _push_then_state(cw, asg_name: str, alarm_name: str, value: float) -> str:
    """Publish one datapoint for the alarm's metric, then report the alarm's state.

    The caller's poll loop keeps the metric at `value` until the alarm has evaluated it.
    """
    cw.put_metric_data(
        Namespace=_NAMESPACE,
        MetricData=[{
            "MetricName": _METRIC,
            "Dimensions": [{"Name": "AutoScalingGroupName", "Value": asg_name}],
            "Value": value,
            "Unit": "None",
        }],
    )
    alarms = cw.describe_alarms(AlarmNames=[alarm_name]).get("MetricAlarms", [])
    return alarms[0]["StateValue"] if alarms else "absent"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
