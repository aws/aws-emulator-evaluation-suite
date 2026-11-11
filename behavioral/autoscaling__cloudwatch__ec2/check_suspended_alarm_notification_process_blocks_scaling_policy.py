"""suspended-alarm-notification-process-blocks-scaling-policy."""

from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "suspended-alarm-notification-process-blocks-scaling-policy"

GROUP = "alerting"

SERVICES = ["autoscaling", "cloudwatch", "ec2"]

_NAMESPACE = "sim2real/autoscaling"
_METRIC = "ScaleOutSignal"
_THRESHOLD = 70.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:e2e", "concern:metrics", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """Suspending the Auto Scaling `AlarmNotification` process makes the group ignore alarm-driven
    scaling: the alarm still fires and an unsuspended twin on the same alarm scales, while the
    suspended group's capacity does not move until the process is resumed.
    """
    as_ = ctx.client("autoscaling")
    cw = ctx.client("cloudwatch")

    # Launch stays suspended on both groups, so capacity changes are recorded without instances.
    asg = _make_empty_asg(ctx)
    twin = _make_empty_asg(ctx)
    for group_name in (asg, twin):
        as_.suspend_processes(AutoScalingGroupName=group_name, ScalingProcesses=["Launch"])

    def _put_policy(group_name: str) -> str:
        policy_name = _xname(ctx, "policy")
        arn = as_.put_scaling_policy(
            AutoScalingGroupName=group_name,
            PolicyName=policy_name,
            PolicyType="SimpleScaling",
            AdjustmentType="ExactCapacity",
            ScalingAdjustment=2,
            Cooldown=0,
        )["PolicyARN"]
        ctx.on_cleanup(
            lambda: ctx.client("autoscaling").delete_policy(
                AutoScalingGroupName=group_name, PolicyName=policy_name
            )
        )
        return arn

    policy_arn = _put_policy(asg)
    twin_policy_arn = _put_policy(twin)
    # One alarm drives both policies, so one transition dispatches both actions at once.
    alarm = _put_asg_alarm(ctx, [policy_arn, twin_policy_arn], asg)

    # Break exactly one thing, on the subject only.
    as_.suspend_processes(AutoScalingGroupName=asg, ScalingProcesses=["AlarmNotification"])
    suspended = {
        p["ProcessName"] for p in _describe_asg(as_, asg).get("SuspendedProcesses", [])
    }
    assert "AlarmNotification" in suspended, (
        f"SuspendProcesses(['AlarmNotification']) must be recorded on the group, "
        f"SuspendedProcesses={sorted(suspended)}"
    )

    # The alarm side is untouched by the suspension. A real breach of a metric this check owns,
    # not SetAlarmState: Auto Scaling declines scaling actions arising from SetAlarmState.
    state = _poll_until(
        lambda: _push_then_state(cw, asg, alarm, _THRESHOLD * 2),
        lambda s: s == "ALARM",
        timeout_s=600,
        interval_s=20.0,
        description=f"{alarm} transitions to ALARM despite the suspended process",
    )
    assert state == "ALARM", (
        f"a suspended Auto Scaling process must not affect the CloudWatch alarm state machine; "
        f"{alarm} is {state!r}"
    )
    # Positive control ordered after the forbidden event: the twin obeys the same transition.
    _poll_until(
        lambda: _describe_asg(as_, twin)["DesiredCapacity"],
        lambda d: d == 2,
        timeout_s=300,
        interval_s=2.0,
        description=f"the unsuspended twin {twin} scales to DesiredCapacity 2 on {alarm}",
    )
    still_empty = _describe_asg(as_, asg)
    assert still_empty["DesiredCapacity"] == 0, (
        f"{asg} DesiredCapacity must stay 0 while AlarmNotification is suspended, even though "
        f"the twin on the same alarm scaled; it is {still_empty['DesiredCapacity']}"
    )
    assert not still_empty.get("Instances"), (
        f"no instance may be provisioned while alarm-driven scaling is suspended, found "
        f"{len(still_empty.get('Instances', []))}"
    )

    # Control on the same group + same alarm: resume ONLY AlarmNotification (Launch stays
    # suspended, so capacity still moves without provisioning).
    as_.resume_processes(AutoScalingGroupName=asg, ScalingProcesses=["AlarmNotification"])
    _poll_until(
        lambda: _push_then_state(cw, asg, alarm, 0.0),
        lambda s: s == "OK",
        timeout_s=600,
        interval_s=20.0,
        description=f"{alarm} returns to OK before the control transition",
    )
    _poll_until(
        lambda: _push_then_state(cw, asg, alarm, _THRESHOLD * 2),
        lambda s: s == "ALARM",
        timeout_s=600,
        interval_s=20.0,
        description=f"{alarm} fires again with AlarmNotification resumed",
    )
    group = _poll_until(
        lambda: _describe_asg(as_, asg),
        lambda g: g["DesiredCapacity"] == 2,
        timeout_s=300,
        interval_s=2.0,
        description=(
            f"once AlarmNotification is resumed, {alarm} executes the policy and raises "
            f"{asg} DesiredCapacity to 2"
        ),
    )
    assert group["DesiredCapacity"] == 2, (
        f"the control case must scale, proving the suppression came from the suspended "
        f"process and not from broken wiring; DesiredCapacity is {group['DesiredCapacity']}"
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
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
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
    """Newest Amazon Linux 2023 AMI, read straight from EC2 (no SSM: it is outside SERVICES).

    The pattern must match a real AMI *name* (``al2023-ami-2023.12.20260831.0-kernel-6.12-x86_64``),
    NOT the SSM alias ``al2023-ami-kernel-default-x86_64`` — that alias only exists under
    ``/aws/service/ami-amazon-linux-latest/`` and as a describe_images name filter it matches zero
    images in every region, which silently self-skipped this check instead of failing.
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
    """A launch template that tags instances and volumes AT CREATION, so they stay attributable."""
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
    # Registered first => runs LAST: delete the group.
    ctx.on_cleanup(
        lambda: ctx.client("autoscaling").delete_auto_scaling_group(
            AutoScalingGroupName=name, ForceDelete=True
        )
    )
    # Registered second => runs FIRST: wind capacity down to zero before deleting, so no instance
    # can survive a partial teardown.
    ctx.on_cleanup(
        lambda: ctx.client("autoscaling").update_auto_scaling_group(
            AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0
        )
    )
    return name


def _put_asg_alarm(ctx, policy_arns: list[str], asg_name: str) -> str:
    """A metric alarm whose ONLY actions are the given scaling policy ARNs."""
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
        ActionsEnabled=True,
        AlarmActions=policy_arns,
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
