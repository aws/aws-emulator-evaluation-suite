"""target-tracking-high-resolution-custom-metric-scales-out-by-the-ratio."""
from __future__ import annotations

import json
import math
import time

from behavioral_harness import tags

# PutScalingPolicy(TargetTrackingScaling) with a CustomizedMetricSpecification Period of 10 mints
# two alarms, `TargetTracking-<group>-AlarmHigh-<uuid>` above the TargetValue and
# `...-AlarmLow-<uuid>` below it, both on the policy's metric at that 10-second period and acting on
# the policy. The early-scale-in probe below is shorter than AlarmLow's own
# EvaluationPeriods * Period, read off the alarm, so it is a negative: AlarmLow cannot reach ALARM
# inside it.

CHECK = "target-tracking-high-resolution-custom-metric-scales-out-by-the-ratio"
GROUP = "alerting"
SERVICES = ["autoscaling", "cloudwatch", "ec2"]

NAMESPACE = "sim2real/autoscaling"
METRIC = "ScaleSignal"
TARGET_VALUE = 50.0
#: The metric period the policy tracks at, and the resolution this check publishes at.
PERIOD_S = 10
AT_TARGET = 50.0          # fed to both groups first, then to the control throughout
BREACH = 150.0            # fed to the subject: ceil(1 * 150 / 50) = 3
BELOW_SCALE_IN = 10.0     # fed to the subject after scale-out, for the early-scale-in probe
EXPECTED_DESIRED = math.ceil(1 * BREACH / TARGET_VALUE)   # 3, not 1 + 1
MAX_SIZE = 4
TICK_S = 5                # shorter than PERIOD_S, so every period holds a datapoint
SETTLE_BOUND_S = 300      # both instances InService AND both AlarmHigh in OK
SCALE_OUT_BOUND_S = 240   # the hard cap on the closed loop itself
SCALE_IN_PROBE_S = 60     # strictly shorter than AlarmLow's own evaluation window
ACTIVITY_BOUND_S = 240    # the scale-out activity reaching StatusCode=Successful


# timing:real-time — metric: 10 s
@tags(
    "axis:happy-path",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A target-tracking policy on a high-resolution CUSTOM metric (Period 10) closes the loop from
    real PutMetricData datapoints to an Auto Scaling capacity change of exactly
    ceil(capacity * metric / target), and its alarms evaluate at that 10-second period.

    Reference: https://docs.aws.amazon.com/autoscaling/ec2/userguide/policy-creating-high-resolution-metrics.html
    """
    asg = ctx.client("autoscaling")
    cw = ctx.client("cloudwatch")

    ami = _al2023_ami(ctx)
    _vpc, _azs, subnets = _network(ctx, "t3.micro", want=2)
    lt_name = _launch_template(ctx, ami)

    groups: list[str] = []
    # ONE net that waits for every group to disappear, registered BEFORE the groups so LIFO
    # runs it after both deletes have been issued: the wait is the max, not the sum.
    ctx.on_cleanup(lambda: _wait_groups_gone(ctx, groups))
    subject = _create_asg(ctx, lt_name, subnets, min_size=1, max_size=MAX_SIZE, desired=1)
    groups.append(subject)
    control = _create_asg(ctx, lt_name, subnets, min_size=1, max_size=MAX_SIZE, desired=1)
    groups.append(control)

    policies = {}
    for label, group in (("subject", subject), ("control", control)):
        name = ctx.unique_name("sim2real-xsvc-tt-")
        asg.put_scaling_policy(
            AutoScalingGroupName=group,
            PolicyName=name,
            PolicyType="TargetTrackingScaling",
            TargetTrackingConfiguration={
                "CustomizedMetricSpecification": {
                    "Namespace": NAMESPACE,
                    "MetricName": METRIC,
                    "Dimensions": [{"Name": "AutoScalingGroupName", "Value": group}],
                    "Statistic": "Average",
                    "Period": PERIOD_S,
                },
                "TargetValue": TARGET_VALUE,
                "DisableScaleIn": False,
            },
        )
        ctx.on_cleanup(lambda g=group, n=name: _unless_gone(
            lambda: asg.delete_policy(AutoScalingGroupName=g, PolicyName=n)))
        policies[label] = _policy(ctx, group, name)
        echoed = policies[label]["TargetTrackingConfiguration"]["CustomizedMetricSpecification"]
        assert echoed.get("Period") == PERIOD_S, (
            f"the {label} policy reports CustomizedMetricSpecification {echoed!r}; expected "
            f"Period {PERIOD_S}"
        )

    alarms = {
        label: _owned_alarms(ctx, group, policies[label], label)
        for label, group in (("subject", subject), ("control", control))
    }
    s_high, s_low = alarms["subject"]
    c_high, _c_low = alarms["control"]

    # ---- phase 1: both groups at target until both instances serve and both AlarmHigh are OK
    def feed(values: dict[str, float]) -> None:
        for group, value in values.items():
            cw.put_metric_data(
                Namespace=NAMESPACE,
                MetricData=[{
                    "MetricName": METRIC,
                    "Dimensions": [{"Name": "AutoScalingGroupName", "Value": group}],
                    "Value": value,
                    "StorageResolution": 1,
                }],
            )

    control_desired_seen: list[int] = []

    def settled() -> dict:
        feed({subject: AT_TARGET, control: AT_TARGET})
        snap = {
            "subject_inservice": len(_ids_in_state(ctx, subject, "InService")),
            "control_inservice": len(_ids_in_state(ctx, control, "InService")),
            "subject_high": _alarm_state(ctx, s_high),
            "control_high": _alarm_state(ctx, c_high),
            "subject_desired": _group(ctx, subject)["DesiredCapacity"],
            "control_desired": _group(ctx, control)["DesiredCapacity"],
        }
        control_desired_seen.append(snap["control_desired"])
        assert snap["subject_desired"] == 1 and snap["control_desired"] == 1, (
            f"no group may move while both are fed the at-target value {AT_TARGET}: {snap!r}"
        )
        return snap

    _poll(
        settled,
        lambda s: s["subject_inservice"] == 1 and s["control_inservice"] == 1
        and s["subject_high"] == "OK" and s["control_high"] == "OK",
        timeout_s=SETTLE_BOUND_S,
        interval_s=TICK_S,
        description="both groups at one InService instance with AlarmHigh in OK",
    )
    breach_started = time.time()

    # ---- phase 2: the subject breaches, the control stays at target
    def loop_tick() -> dict:
        feed({subject: BREACH, control: AT_TARGET})
        snap = {
            "subject_desired": _group(ctx, subject)["DesiredCapacity"],
            "control_desired": _group(ctx, control)["DesiredCapacity"],
            "subject_high": _alarm_state(ctx, s_high),
            "control_high": _alarm_state(ctx, c_high),
            "elapsed_s": round(time.time() - breach_started),
        }
        control_desired_seen.append(snap["control_desired"])
        assert snap["control_desired"] == 1, (
            f"the control group fed exactly the target value must stay at desired 1, got "
            f"{snap!r}"
        )
        assert snap["control_high"] != "ALARM", (
            f"the control's AlarmHigh must not breach on a value equal to its threshold: "
            f"{snap!r}"
        )
        return snap

    first_move = _poll(
        loop_tick,
        lambda s: s["subject_desired"] != 1,
        timeout_s=SCALE_OUT_BOUND_S,
        interval_s=TICK_S,
        description=(
            f"the subject fed {BREACH} against target {TARGET_VALUE} changed DesiredCapacity "
            f"away from 1"
        ),
    )
    assert first_move["subject_desired"] == EXPECTED_DESIRED, (
        f"target tracking is proportional: ceil(1 * {BREACH} / {TARGET_VALUE}) = "
        f"{EXPECTED_DESIRED}, but the first capacity the subject moved to was "
        f"{first_move['subject_desired']!r} ({first_move!r})"
    )

    # ---- phase 3: early-scale-in probe, while the scale-out activity completes
    low_alarm = _alarm(ctx, s_low)
    low_window_s = low_alarm["Period"] * low_alarm["EvaluationPeriods"]
    assert SCALE_IN_PROBE_S < low_window_s, (
        f"the early-scale-in probe ({SCALE_IN_PROBE_S}s) must be shorter than AlarmLow's own "
        f"evaluation window, Period*EvaluationPeriods = {low_window_s}s, or it proves nothing"
    )
    assert low_alarm["Threshold"] < TARGET_VALUE and BELOW_SCALE_IN < low_alarm["Threshold"], (
        f"the probe value {BELOW_SCALE_IN} must breach AlarmLow's threshold "
        f"{low_alarm['Threshold']!r}, which must sit below the target {TARGET_VALUE}"
    )
    probe_started = time.time()

    def probe_tick() -> dict:
        feed({subject: BELOW_SCALE_IN, control: AT_TARGET})
        snap = {
            "subject_desired": _group(ctx, subject)["DesiredCapacity"],
            "control_desired": _group(ctx, control)["DesiredCapacity"],
            "subject_low": _alarm_state(ctx, s_low),
            "activity": _scale_out_activity(ctx, subject, s_high),
            "elapsed_s": round(time.time() - probe_started),
        }
        control_desired_seen.append(snap["control_desired"])
        assert snap["subject_low"] != "ALARM", (
            f"AlarmLow reached ALARM {snap['elapsed_s']}s into low data, inside its own "
            f"{low_window_s}s evaluation window: {snap!r}"
        )
        assert snap["subject_desired"] >= EXPECTED_DESIRED, (
            f"capacity dropped below {EXPECTED_DESIRED} before AlarmLow could legitimately "
            f"fire: {snap!r}"
        )
        assert snap["control_desired"] == 1, f"the control group moved: {snap!r}"
        return snap

    final = _poll(
        probe_tick,
        lambda s: s["elapsed_s"] >= SCALE_IN_PROBE_S and s["activity"] is not None
        and s["activity"]["StatusCode"] == "Successful",
        timeout_s=ACTIVITY_BOUND_S,
        interval_s=TICK_S,
        description=(
            "the early-scale-in window elapsed AND the scale-out activity reached Successful"
        ),
    )
    activity = final["activity"]
    assert s_high in activity["Cause"], (
        f"the scale-out activity's Cause must name the alarm that drove it, {s_high!r}: "
        f"{activity['Cause']!r}"
    )
    assert f"changing the desired capacity from 1 to {EXPECTED_DESIRED}" in activity["Cause"], (
        f"the scale-out activity's Cause must record the proportional change from 1 to "
        f"{EXPECTED_DESIRED}: {activity['Cause']!r}"
    )
    assert final["subject_low"] in ("OK", "INSUFFICIENT_DATA"), (
        f"AlarmLow must still be un-fired at the end of the bounded probe: {final!r}"
    )

    # ---- CloudWatch's own record of the transition that drove it
    transitions = _state_transitions(ctx, s_high)
    assert ("OK", "ALARM") in transitions, (
        f"AlarmHigh's history must record an OK -> ALARM transition, got {transitions!r}"
    )
    control_transitions = _state_transitions(ctx, c_high)
    assert ("OK", "ALARM") not in control_transitions and all(
        new != "ALARM" for _old, new in control_transitions
    ), (
        f"the control's AlarmHigh must never have entered ALARM, history {control_transitions!r}"
    )
    assert ("INSUFFICIENT_DATA", "OK") in control_transitions, (
        f"the control's AlarmHigh must have evaluated real datapoints (INSUFFICIENT_DATA -> OK), "
        f"history {control_transitions!r}"
    )

    # ---- the control never scaled: no ALARM-driven activity at all on its group. (Its one
    # capacity change is the creation itself -- measured: "a user request created an
    # AutoScalingGroup changing the desired capacity from 0 to 1" -- which names no alarm.)
    assert set(control_desired_seen) == {1}, (
        f"the control's DesiredCapacity must be 1 at every observation, saw "
        f"{sorted(set(control_desired_seen))!r}"
    )
    control_activities = _activities(ctx, control)
    alarm_driven = [
        a["Cause"] for a in control_activities
        if c_high in a["Cause"] or _c_low in a["Cause"] or "triggered policy" in a["Cause"]
    ]
    assert not alarm_driven, (
        f"the control group must record no alarm-driven activity, got {alarm_driven!r}"
    )
    assert any("from 0 to 1" in a["Cause"] for a in control_activities), (
        f"the control's activity history must still record its own creation (0 -> 1), so the "
        f"absence above is read from a live history: {[a['Cause'] for a in control_activities]!r}"
    )


def _policy(ctx, group: str, policy: str) -> dict:
    paginator = ctx.client("autoscaling").get_paginator("describe_policies")
    for page in paginator.paginate(AutoScalingGroupName=group):
        for record in page["ScalingPolicies"]:
            if record["PolicyName"] == policy:
                return record
    raise AssertionError(f"scaling policy {policy!r} not found on group {group!r}")


def _alarms_named(ctx, names: list[str]) -> list[dict]:
    fetched: list[dict] = []
    paginator = ctx.client("cloudwatch").get_paginator("describe_alarms")
    for page in paginator.paginate(AlarmNames=names):
        fetched += page.get("MetricAlarms", [])
    return fetched


def _alarm(ctx, name: str) -> dict:
    found = _alarms_named(ctx, [name])
    assert len(found) == 1, f"expected exactly one alarm named {name!r}, got {found!r}"
    return found[0]


def _alarm_state(ctx, name: str) -> str:
    return _alarm(ctx, name)["StateValue"]


def _owned_alarms(ctx, group: str, policy: dict, label: str) -> tuple[str, str]:
    """The policy's two alarms, read AT CLOUDWATCH and held to the policy's own spec.

    Returns (AlarmHigh name, AlarmLow name), classified by ComparisonOperator and confirmed by
    the generated name, so a target returning plausible names for alarms it never created, or
    alarms watching the wrong metric, fails here."""
    claimed = sorted(a["AlarmName"] for a in policy.get("Alarms", []))
    assert len(claimed) == 2, (
        f"the {label} policy must own exactly two alarms (AlarmHigh, AlarmLow), got {claimed!r}"
    )
    fetched = _alarms_named(ctx, claimed)
    assert sorted(a["AlarmName"] for a in fetched) == claimed, (
        f"the {label} policy claims alarms CloudWatch does not have: claimed {claimed!r}, "
        f"found {sorted(a['AlarmName'] for a in fetched)!r}"
    )
    arn = policy["PolicyARN"]
    for alarm in fetched:
        observed = {
            "Namespace": alarm.get("Namespace"),
            "MetricName": alarm.get("MetricName"),
            "Dimensions": alarm.get("Dimensions"),
            "Statistic": alarm.get("Statistic"),
            "Period": alarm.get("Period"),
            "AlarmActions": alarm.get("AlarmActions"),
        }
        expected = {
            "Namespace": NAMESPACE,
            "MetricName": METRIC,
            "Dimensions": [{"Name": "AutoScalingGroupName", "Value": group}],
            "Statistic": "Average",
            "Period": PERIOD_S,
            "AlarmActions": [arn],
        }
        assert observed == expected, (
            f"{alarm['AlarmName']} must watch exactly the policy's custom metric and act only "
            f"on the policy: got {observed!r}, expected {expected!r}"
        )
    high = [a for a in fetched if a["ComparisonOperator"] == "GreaterThanThreshold"]
    low = [a for a in fetched if a["ComparisonOperator"] == "LessThanThreshold"]
    assert len(high) == 1 and len(low) == 1, (
        f"the {label} policy must own one GreaterThanThreshold and one LessThanThreshold alarm, "
        f"got {[(a['AlarmName'], a['ComparisonOperator']) for a in fetched]!r}"
    )
    assert "-AlarmHigh-" in high[0]["AlarmName"] and "-AlarmLow-" in low[0]["AlarmName"], (
        f"the scale-out alarm must be the AlarmHigh and the scale-in one the AlarmLow: "
        f"{high[0]['AlarmName']!r} / {low[0]['AlarmName']!r}"
    )
    assert high[0]["Threshold"] == TARGET_VALUE, (
        f"AlarmHigh must fire above the TargetValue {TARGET_VALUE}, got {high[0]['Threshold']!r}"
    )
    return high[0]["AlarmName"], low[0]["AlarmName"]


def _state_transitions(ctx, alarm_name: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    paginator = ctx.client("cloudwatch").get_paginator("describe_alarm_history")
    for page in paginator.paginate(AlarmName=alarm_name, HistoryItemType="StateUpdate"):
        for item in page.get("AlarmHistoryItems", []):
            data = json.loads(item["HistoryData"])
            out.append((data["oldState"]["stateValue"], data["newState"]["stateValue"]))
    return out


def _activities(ctx, group: str) -> list[dict]:
    out: list[dict] = []
    paginator = ctx.client("autoscaling").get_paginator("describe_scaling_activities")
    for page in paginator.paginate(AutoScalingGroupName=group):
        out += page["Activities"]
    return out


def _scale_out_activity(ctx, group: str, alarm_name: str):
    """The FIRST activity the alarm-driven policy produced, or None if none is recorded yet.

    The earliest by StartTime, because a metric that stays high can drive a later, second
    step (3 -> 4) whose activity must not stand in for the first one."""
    matches = [
        a for a in _activities(ctx, group)
        if alarm_name in a["Cause"] and "changing the desired capacity" in a["Cause"]
    ]
    if not matches:
        return None
    first = min(matches, key=lambda a: a["StartTime"])
    return {"StatusCode": first["StatusCode"], "Cause": first["Cause"],
            "ActivityId": first["ActivityId"]}


_MANAGED_TAGS = {"sim2real": CHECK, "sim2real:managed": "true"}


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


def _unless_code(fn, gone_code: str) -> None:
    """Run one delete; only the resource's not-found code means already gone, the rest raise."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code", "") != gone_code:
            raise


def _poll(fn, pred, *, timeout_s, interval_s=10, description="condition"):
    """Poll fn() until pred() holds; RAISE with the last observed value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


def _al2023_ami(ctx) -> str:
    """Latest Amazon-owned AL2023 x86_64 image, resolved through EC2 itself (no SSM)."""
    images = ctx.client("ec2").describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-kernel-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    assert images, f"no available Amazon-owned AL2023 x86_64 image in {ctx.region}"
    return max(images, key=lambda i: i["CreationDate"])["ImageId"]


def _network(ctx, instance_type: str, want: int):
    """A DEDICATED VPC with `want` subnets, in AZs that really offer instance_type."""
    ec2 = ctx.client("ec2")
    offered = sorted(
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    )
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    }
    azs = [z for z in offered if z in available][:want]
    assert len(azs) == want, (
        f"need {want} available AZs offering {instance_type!r} in {ctx.region}, got {azs!r} "
        f"(offered={offered!r})"
    )

    vpc_id = ec2.create_vpc(
        CidrBlock="10.223.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _unless_code(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id),
                             "InvalidVpcID.NotFound")
    )

    subnet_ids = []
    for index, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.223.{index}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sn=subnet_id: _unless_code(
                lambda: _delete_net(ec2, "delete_subnet", SubnetId=sn), "InvalidSubnetID.NotFound"
            )
        )
        subnet_ids.append(subnet_id)
    return vpc_id, azs, subnet_ids


def _launch_template(ctx, ami: str, *, instance_type: str = "t3.micro") -> str:
    """Tag BOTH the instance and its volume AT LAUNCH, so the server-minted ids an ASG
    creates stay attributable to this check and reapable if teardown loses one."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-xsvc-as-lt-")
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
    ctx.on_cleanup(
        lambda: _unless_code(
            lambda: ec2.delete_launch_template(LaunchTemplateName=name),
            "InvalidLaunchTemplateName.NotFoundException",
        )
    )
    return name


def _create_asg(ctx, lt_name: str, subnets, *, min_size: int, max_size: int,
                desired: int) -> str:
    asg = ctx.client("autoscaling")
    name = ctx.unique_name("sim2real-xsvc-as-grp-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=",".join(subnets),
        HealthCheckGracePeriod=0,
        # A scale-out activity stays WaitingForInstanceWarmup for the warmup period after its
        # instances enter InService; a default instance warmup of 0 completes it at InService.
        DefaultInstanceWarmup=0,
        Tags=[
            {"Key": k, "Value": v, "PropagateAtLaunch": True} for k, v in _MANAGED_TAGS.items()
        ],
    )

    def _drop():
        # Issue the delete only; the shared net registered earlier waits for every group, so
        # two groups' terminations overlap instead of queueing.
        _unless_gone(lambda: asg.update_auto_scaling_group(
            AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0))
        _unless_gone(lambda: asg.delete_auto_scaling_group(
            AutoScalingGroupName=name, ForceDelete=True))

    ctx.on_cleanup(_drop)
    return name


def _wait_groups_gone(ctx, names: list[str]) -> None:
    pending = list(names)
    for _ in range(450):
        pending = [n for n in pending if _describe_groups(ctx, n)]
        if not pending:
            return
        time.sleep(2)
    raise RuntimeError(f"auto scaling groups {pending!r} still present after ForceDelete")


def _describe_groups(ctx, name: str) -> list:
    """Paginated: a filtered Describe can still return several pages."""
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


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes: an asynchronous
# delete in this VPC leaves its ENIs behind briefly, so DeleteSubnet / DeleteVpc retries
# DependencyViolation within one shared window, then raises naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
