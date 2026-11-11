"""suspending-alarm-notification-blocks-the-policy-driven-scale-out."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "suspending-alarm-notification-blocks-the-policy-driven-scale-out"
GROUP = "overly-permissive"
SERVICES = ["autoscaling", "cloudwatch", "ec2"]

_NAMESPACE = "sim2real/autoscaling"
_METRIC = "ScaleOutSignal"
_THRESHOLD = 50.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """A suspended AlarmNotification process makes the ASG ignore a genuine custom-metric alarm
    it otherwise obeys; after ResumeProcesses the same alarm, policy and group do launch an
    instance, which bounds the absence.
    """
    asg = ctx.client("autoscaling")
    cw = ctx.client("cloudwatch")

    ami = _al2023_ami(ctx)
    _vpc, subnets = _usable_subnets(ctx, "t3.micro", want=2)
    lt_name = _launch_template(ctx, ami)
    name = _create_asg(ctx, lt_name, subnets, min_size=1, max_size=3, desired=1)

    ids_before = set(_poll(
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=900,
        description="setup: the group reached 1 InService instance",
    ))

    policy_name = ctx.unique_name("sim2real-xsvc-pol-")
    policy_arn = asg.put_scaling_policy(
        AutoScalingGroupName=name,
        PolicyName=policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
        Cooldown=0,
    )["PolicyARN"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: asg.delete_policy(
        AutoScalingGroupName=name, PolicyName=policy_name
    )))

    alarm_name = ctx.unique_name("sim2real-xsvc-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        AlarmDescription="sim2real asg scale-out trigger on a custom metric",
        Namespace=_NAMESPACE,
        MetricName=_METRIC,
        Dimensions=[{"Name": "AutoScalingGroupName", "Value": name}],
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        AlarmActions=[policy_arn],
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))
    alarm = _poll(
        lambda: _alarm(ctx, alarm_name),
        lambda a: a is not None,
        timeout_s=120,
        interval_s=5,
        description=f"alarm {alarm_name} is visible in DescribeAlarms",
    )
    assert alarm["AlarmActions"] == [policy_arn], (
        f"the alarm does not carry the scaling policy as its action: {alarm['AlarmActions']!r}"
    )

    # --- Break exactly one thing.
    asg.suspend_processes(AutoScalingGroupName=name, ScalingProcesses=["AlarmNotification"])
    ctx.on_cleanup(lambda: _unless_gone(lambda: asg.resume_processes(
        AutoScalingGroupName=name, ScalingProcesses=["AlarmNotification"]
    )))
    suspended = {p["ProcessName"] for p in _group(ctx, name)["SuspendedProcesses"]}
    assert suspended == {"AlarmNotification"}, (
        f"exactly AlarmNotification must be suspended for the absence below to be attributable: "
        f"{sorted(suspended)!r}"
    )

    state = _poll(
        lambda: _push_then_state(ctx, name, alarm_name, _THRESHOLD * 2),
        lambda s: s == "ALARM",
        timeout_s=600,
        interval_s=20,
        description=f"the breaching datapoint drove alarm {alarm_name} into ALARM while suspended",
    )
    assert state == "ALARM", (
        f"the alarm never evaluated the breaching datapoint into ALARM, so nothing below is "
        f"evidence about the suspension: {state!r}"
    )
    # CloudWatch must record that it DID hand the alarm to the policy. This is what localises the
    # suppression to Auto Scaling rather than to a notification that never happened.
    action = _poll(
        lambda: _action_history(ctx, alarm_name, policy_arn),
        lambda items: bool(items),
        timeout_s=300,
        interval_s=10,
        description=f"CloudWatch recorded invoking {policy_name} while the process was suspended",
    )[0]
    assert action["actionState"] == "Succeeded", (
        f"CloudWatch never successfully invoked the policy, so the absence below says nothing about "
        f"the suspension: {action!r}"
    )

    # The effect that must be ABSENT: no capacity change, no launch. The metric is kept breaching
    # throughout, so the alarm stays in ALARM and the suppression is being exercised continuously.
    held = _holds_for(
        lambda: (_group(ctx, name)["DesiredCapacity"],
                 set(_ids_in_state(ctx, name, "InService", "Pending", "Pending:Wait")),
                 _push_then_state(ctx, name, alarm_name, _THRESHOLD * 2)),
        lambda triple: triple[0] == 1 and triple[1] == ids_before and triple[2] == "ALARM",
        seconds=240,
        interval_s=20,
        description="with AlarmNotification suspended a firing alarm must change nothing",
    )
    assert held[0] == 1 and held[1] == ids_before, (
        f"the suspended group scaled out on the alarm anyway: {held!r}, expected DesiredCapacity 1 "
        f"and instances {sorted(ids_before)!r}"
    )
    assert not [a for a in _activities(ctx, name) if policy_name in a.get("Cause", "")], (
        f"a scaling activity attributed to {policy_name!r} was recorded while AlarmNotification "
        f"was suspended: "
        f"{[a.get('Cause') for a in _activities(ctx, name) if policy_name in a.get('Cause', '')]!r}"
    )

    # --- Repair the one broken thing, then force a fresh OK -> ALARM transition so the alarm has
    # something to notify about: Auto Scaling acts on the transition, not on the standing state.
    asg.resume_processes(AutoScalingGroupName=name, ScalingProcesses=["AlarmNotification"])
    _poll(
        lambda: _group(ctx, name)["SuspendedProcesses"],
        lambda procs: not procs,
        timeout_s=120,
        interval_s=5,
        description="the group reports nothing suspended after the resume",
    )
    ok_state = _poll(
        lambda: _push_then_state(ctx, name, alarm_name, 0.0),
        lambda s: s == "OK",
        timeout_s=600,
        interval_s=20,
        description=f"a non-breaching datapoint returned alarm {alarm_name} to OK",
    )
    assert ok_state == "OK", f"the alarm did not return to OK before the repair leg: {ok_state!r}"
    state = _poll(
        lambda: _push_then_state(ctx, name, alarm_name, _THRESHOLD * 2),
        lambda s: s == "ALARM",
        timeout_s=600,
        interval_s=20,
        description=f"alarm {alarm_name} fired again after the resume",
    )
    assert state == "ALARM", f"the alarm did not fire again after the resume: {state!r}"

    desired_after = _poll(
        lambda: _group(ctx, name)["DesiredCapacity"],
        lambda d: d > 1,
        timeout_s=900,
        interval_s=10,
        description="after the resume the firing alarm raised DesiredCapacity",
    )
    assert desired_after > 1, (
        f"resuming AlarmNotification did not restore the scale-out: DesiredCapacity is still "
        f"{desired_after!r}"
    )
    in_service = _poll(
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == desired_after,
        timeout_s=900,
        interval_s=15,
        description=f"the resumed group launched its {desired_after} instances",
    )
    new_ids = set(in_service) - ids_before
    assert new_ids, (
        f"the resumed scale-out launched no new instance: {sorted(in_service)!r} vs "
        f"{sorted(ids_before)!r}"
    )
    for iid in new_ids:
        ec2_state = _ec2_state(ctx, iid)
        assert ec2_state == "running", (
            f"the scale-out instance {iid} is not running: {ec2_state!r}"
        )
    attributing = _poll(
        lambda: [a for a in _activities(ctx, name) if policy_name in a.get("Cause", "")],
        lambda acts: bool(acts),
        timeout_s=300,
        interval_s=10,
        description=f"a scaling activity now attributes the change to policy {policy_name}",
    )
    assert attributing, (
        f"no scaling activity attributes the resumed change to {policy_name!r}; the causes were "
        f"{[a.get('Cause') for a in _activities(ctx, name)]!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = {"sim2real": "as-alarm-susp", "sim2real:managed": "true"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _unless_gone(fn):
    """Run one teardown call: only a not-found answer means already gone; a busy group is
    retried every 2 s for 60 s; every other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code", "")
            if "NotFound" in code or code == "NoSuchEntity" or (
                code == "ValidationError" and "not found" in err.get("Message", "").lower()
            ):
                return None
            if code not in ("ScalingActivityInProgress", "ResourceInUse", "ResourceContention") or (
                time.monotonic() >= deadline
            ):
                raise
        time.sleep(2)


def _poll(fn, pred, *, timeout_s, interval_s=10, description="condition"):
    """Poll fn() until pred() holds; raise with the last observed value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


def _holds_for(fn, pred, *, seconds, interval_s=10, description="condition"):
    """Assert pred() holds continuously for `seconds` -- proves an effect stayed ABSENT."""
    deadline = time.monotonic() + seconds
    while True:
        val = fn()
        if not pred(val):
            raise AssertionError(f"{description} stopped holding; observed {val!r}")
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)


def _al2023_ami(ctx) -> str:
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    value = ctx.client("ssm").get_parameter(Name=param)["Parameter"]["Value"]
    assert value.startswith("ami-"), f"{param} did not resolve to an AMI: {value!r}"
    return value


def _usable_subnets(ctx, instance_type: str, want: int = 1):
    """Default-VPC subnets in AZs that ACTUALLY OFFER instance_type.

    Both halves are load-bearing: describe_instance_type_offerings does not report zone STATE, so
    an impaired zone still appears as offering the type, and describe_availability_zones says
    nothing about instance types.
    """
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to launch instances into")
    vpc_id = vpcs[0]["VpcId"]
    subnets = []
    for page in ec2.get_paginator("describe_subnets").paginate(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
    ]):
        subnets += page["Subnets"]
    per_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["SubnetId"]):
        if sn["AvailabilityZone"] in (offered & available) and sn.get(
            "AvailableIpAddressCount", 0
        ) > 0:
            per_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    ids = [per_az[az] for az in sorted(per_az)]
    assert len(ids) >= want, (
        f"need {want} shared-network subnets in AZs offering {instance_type!r}, found {ids!r}; "
        f"offered={sorted(offered)!r}, available={sorted(available)!r}"
    )
    return vpc_id, ids[:want]


def _launch_template(ctx, ami: str, *, instance_type: str = "t3.micro") -> str:
    """A launch template tagging BOTH the instance and its volume AT LAUNCH, so the
    server-minted instance and volume ids an ASG creates stay attributable and reapable."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(_XSVC_PREFIX + "lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami,
            "InstanceType": instance_type,
            "TagSpecifications": [
                {"ResourceType": "instance", "Tags": _tags_kv()},
                {"ResourceType": "volume", "Tags": _tags_kv()},
            ],
        },
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
    )

    def _drop():
        for _ in range(12):
            try:
                ec2.delete_launch_template(LaunchTemplateName=name)
                return
            except Exception:  # noqa: BLE001 - still referenced by a deleting ASG
                time.sleep(10)
        raise RuntimeError(f"launch template {name} could not be deleted")

    ctx.on_cleanup(_drop)
    return name


def _create_asg(ctx, lt_name: str, subnets, *, min_size: int, max_size: int, desired: int,
                **kwargs) -> str:
    asg = ctx.client("autoscaling")
    name = ctx.unique_name(_XSVC_PREFIX + "asg-")
    params = {
        "AutoScalingGroupName": name,
        "LaunchTemplate": {"LaunchTemplateName": lt_name, "Version": "$Latest"},
        "MinSize": min_size,
        "MaxSize": max_size,
        "DesiredCapacity": desired,
        "VPCZoneIdentifier": ",".join(subnets),
        "HealthCheckGracePeriod": 0,
        "Tags": [{"Key": k, "Value": v, "PropagateAtLaunch": True}
                 for k, v in _MANAGED_TAGS.items()],
    }
    params.update(kwargs)
    asg.create_auto_scaling_group(**params)

    def _drop():
        # An ASG left with capacity RELAUNCHES the instances you just deleted, so drain to zero
        # FIRST, then ForceDelete, then WAIT for the group to disappear. Resuming the suspended
        # process first (registered later, so LIFO runs it before this) matters: a group with
        # Terminate or Launch suspended cannot be drained at all.
        _unless_gone(lambda: asg.update_auto_scaling_group(
            AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0))
        _unless_gone(lambda: asg.delete_auto_scaling_group(
            AutoScalingGroupName=name, ForceDelete=True))
        for _ in range(450):
            if not _describe_groups(ctx, name):
                return
            time.sleep(2)
        raise RuntimeError(f"auto scaling group {name} still present after ForceDelete")

    ctx.on_cleanup(_drop)
    return name


def _describe_groups(ctx, name: str) -> list:
    """Paginated: a filtered Describe can still return pages."""
    groups = []
    for page in ctx.client("autoscaling").get_paginator(
        "describe_auto_scaling_groups"
    ).paginate(AutoScalingGroupNames=[name]):
        groups += page["AutoScalingGroups"]
    return groups


def _group(ctx, name: str) -> dict:
    groups = _describe_groups(ctx, name)
    assert groups, f"auto scaling group {name!r} not found"
    return groups[0]


def _ids_in_state(ctx, name: str, *states: str) -> list[str]:
    return sorted(
        i["InstanceId"] for i in _group(ctx, name)["Instances"]
        if i["LifecycleState"] in states
    )


def _alarm(ctx, alarm_name: str):
    """The named metric alarm, found by paginating DescribeAlarms, or None."""
    for page in ctx.client("cloudwatch").get_paginator("describe_alarms").paginate(
        AlarmNamePrefix=alarm_name
    ):
        for alarm in page.get("MetricAlarms", []):
            if alarm["AlarmName"] == alarm_name:
                return alarm
    return None


def _push_then_state(ctx, group: str, alarm_name: str, value: float) -> str:
    """Publish one datapoint for the alarm's metric, then report the alarm's state.

    The publish lives inside the caller's bounded predicate loop because CloudWatch evaluates the
    period it has data for -- a single datapoint can fall outside the window it happens to score
    next -- so the loop keeps the metric at `value` until the alarm has actually evaluated it. This
    is a real breach of a metric this check owns, not a synthetic state: Auto Scaling declines
    scaling actions arising from SetAlarmState.
    """
    ctx.client("cloudwatch").put_metric_data(
        Namespace=_NAMESPACE,
        MetricData=[{
            "MetricName": _METRIC,
            "Dimensions": [{"Name": "AutoScalingGroupName", "Value": group}],
            "Value": value,
            "Unit": "None",
        }],
    )
    alarm = _alarm(ctx, alarm_name)
    return alarm["StateValue"] if alarm else "absent"


def _action_history(ctx, alarm_name: str, target_arn: str) -> list[dict]:
    """Parsed HistoryData for every Action item on the alarm that names target_arn.

    DescribeAlarmHistory with HistoryItemType='Action' is CloudWatch's own record of handing the
    alarm off, carrying actionState and the resource it notified -- which is how the two sides of
    this boundary are told apart: CloudWatch invoking the policy and Auto Scaling acting on it are
    different facts, and only this call reports the first one.
    """
    items = []
    for page in ctx.client("cloudwatch").get_paginator("describe_alarm_history").paginate(
        AlarmName=alarm_name, HistoryItemType="Action"
    ):
        for item in page.get("AlarmHistoryItems", []):
            data = item.get("HistoryData") or "{}"
            if target_arn in data:
                items.append(json.loads(data))
    return items


def _activities(ctx, name: str) -> list[dict]:
    acts = []
    for page in ctx.client("autoscaling").get_paginator(
        "describe_scaling_activities"
    ).paginate(AutoScalingGroupName=name):
        acts += page["Activities"]
    return acts


def _ec2_state(ctx, instance_id: str) -> str:
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=[instance_id]):
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst["State"]["Name"]
    raise AssertionError(f"instance {instance_id!r} not found in DescribeInstances")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
