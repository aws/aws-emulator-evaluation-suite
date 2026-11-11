"""alarm-state-change-drives-the-scaling-policy-to-launch-an-instance."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "alarm-state-change-drives-the-scaling-policy-to-launch-an-instance"
GROUP = "scaling-policy"
SERVICES = ["autoscaling", "cloudwatch", "ec2"]

_NAMESPACE = "sim2real/autoscaling"
_METRIC = "ScaleOutSignal"
_THRESHOLD = 50.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
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
    """A real custom-metric breach drives the alarm to ALARM, CloudWatch records invoking the
    SimpleScaling policy, DesiredCapacity rises, and a new instance reaches InService and running
    with a scaling activity naming the policy.
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
    # delete_policy also removes any alarm the service created for the policy.
    ctx.on_cleanup(lambda: _unless_gone(lambda: asg.delete_policy(
        AutoScalingGroupName=name, PolicyName=policy_name
    )))
    policy = _policy(ctx, name, policy_name)
    assert policy["PolicyARN"] == policy_arn, (
        f"DescribePolicies returned a different ARN than PutScalingPolicy: "
        f"{policy['PolicyARN']!r} != {policy_arn!r}"
    )

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

    # A genuine breach, not SetAlarmState: Auto Scaling declines actions from a temporary alarm
    # state even though CloudWatch reports the hand-off as Succeeded. The push repeats inside the
    # loop because the alarm needs a datapoint in the period it evaluates.
    state = _poll(
        lambda: _push_then_state(ctx, name, alarm_name, _THRESHOLD * 2),
        lambda s: s == "ALARM",
        timeout_s=600,
        interval_s=20,
        description=f"the breaching datapoint drove alarm {alarm_name} into ALARM",
    )
    assert state == "ALARM", (
        f"the alarm never evaluated the breaching datapoint into ALARM: {state!r}"
    )

    # CloudWatch's own record that it invoked THIS policy: the near side of the boundary, asserted
    # separately from Auto Scaling's response so a failure names the side that broke.
    action = _poll(
        lambda: _action_history(ctx, alarm_name, policy_arn),
        lambda items: bool(items),
        timeout_s=300,
        interval_s=10,
        description=f"CloudWatch recorded invoking {policy_name} for alarm {alarm_name}",
    )[0]
    assert action["actionState"] == "Succeeded", (
        f"CloudWatch did not successfully invoke the scaling policy: {action!r}"
    )

    desired_after = _poll(
        lambda: _group(ctx, name)["DesiredCapacity"],
        lambda d: d > 1,
        timeout_s=900,
        interval_s=10,
        description="the alarm raised the group's DesiredCapacity",
    )
    assert desired_after > 1, (
        f"the alarm did not scale the group out: DesiredCapacity is still {desired_after!r}"
    )
    in_service = _poll(
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == desired_after,
        timeout_s=900,
        interval_s=15,
        description=f"the group launched the {desired_after} instances it asked for",
    )
    assert len(in_service) == desired_after, (
        f"the group did not actually launch the capacity it asked for: {in_service!r} for "
        f"DesiredCapacity {desired_after!r}"
    )
    new_ids = set(in_service) - ids_before
    assert new_ids, (
        f"the scale-out reused the original instance set: {sorted(ids_before)!r}"
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
        description=f"a scaling activity attributes the change to policy {policy_name}",
    )
    assert attributing, (
        f"no scaling activity attributes the change to the policy {policy_name!r}; the causes were "
        f"{[a.get('Cause') for a in _activities(ctx, name)]!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = {"sim2real": "as-alarm", "sim2real:managed": "true"}


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
        # FIRST, then ForceDelete, then WAIT for the group to disappear -- only then may the
        # launch-template teardown registered earlier (LIFO: it runs after this) succeed.
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
    """Paginated DescribeAutoScalingGroups for one group name."""
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


def _policy(ctx, group: str, policy_name: str) -> dict:
    """The named policy, found by paginating DescribePolicies."""
    for page in ctx.client("autoscaling").get_paginator("describe_policies").paginate(
        AutoScalingGroupName=group
    ):
        for pol in page["ScalingPolicies"]:
            if pol["PolicyName"] == policy_name:
                return pol
    raise AssertionError(f"scaling policy {policy_name!r} not found on group {group!r}")


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
    """Publish one breaching datapoint for the alarm's metric, then report the alarm's state.

    A single datapoint can fall outside the window CloudWatch scores next, so the caller repeats it.
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

    This is CloudWatch's own record of invoking the policy, separate from Auto Scaling acting on it.
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
