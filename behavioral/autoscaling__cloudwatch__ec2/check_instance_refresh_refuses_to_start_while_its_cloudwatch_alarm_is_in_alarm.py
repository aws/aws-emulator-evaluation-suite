"""instance-refresh-refuses-to-start-while-its-cloudwatch-alarm-is-in-alarm."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-refresh-refuses-to-start-while-its-cloudwatch-alarm-is-in-alarm"
GROUP = "alerting"
SERVICES = ["autoscaling", "cloudwatch", "ec2"]

_REJECTION_CODE = "ValidationError"
_REJECTION_MESSAGE = "A CloudWatch monitor is in alarm. The instance refresh cannot start."
# A replacement's warmup that outlasts every read and Cancel below, so each refresh this check
# starts is still in progress when the check cancels it.
_HOLD_WARMUP_S = 900
_TERMINAL_STATUSES = (
    "Successful", "Failed", "Cancelled", "RollbackSuccessful", "RollbackFailed",
)


@tags(
    "axis:rejection",
    "cap:c4",
    "concern:metrics",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudWatch alarm in ALARM named in AlarmSpecification makes StartInstanceRefresh fail and
    create no refresh, while the identical call succeeds with the alarm OK, before and after.

    Reference: https://docs.aws.amazon.com/autoscaling/ec2/userguide/instance-refresh-rollback.html
    """
    asg = ctx.client("autoscaling")
    cloudwatch = ctx.client("cloudwatch")

    ami = _al2023_ami(ctx)
    _vpc, _azs, subnets = _network(ctx, "t3.micro", want=1)
    lt_name = _launch_template(ctx, ami)
    # Version="1" (not $Latest) keeps the group refresh-eligible under every documented
    # rollback restriction, so the refusal below cannot be confused with a config objection.
    name = _create_asg(
        ctx, lt_name, subnets, min_size=0, max_size=2, desired=1, lt_version="1"
    )
    _poll(
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=_budget_s(ctx, 900),
        interval_s=2,
        ctx=ctx,
        description="setup: the group reached 1 InService instance so a refresh has work to do",
    )

    alarm = ctx.unique_name("sim2real-behav-as-alarm-")
    _put_alarm(ctx, alarm, name, "notBreaching")
    ctx.on_cleanup(lambda: _unless_gone(lambda: cloudwatch.delete_alarms(AlarmNames=[alarm])))
    preferences = {
        "AlarmSpecification": {"Alarms": [alarm]},
        "MinHealthyPercentage": 100,
        "MaxHealthyPercentage": 200,
        "InstanceWarmup": _HOLD_WARMUP_S,
        "SkipMatching": False,
    }

    # With the alarm OK, the call is accepted.
    _force_alarm_state(ctx, alarm, name, "OK")
    accepted = asg.start_instance_refresh(
        AutoScalingGroupName=name, Strategy="Rolling", Preferences=preferences
    )["InstanceRefreshId"]
    seen = _poll(
        lambda: _refresh_ids(ctx, name),
        lambda ids: accepted in ids,
        timeout_s=_budget_s(ctx, 120),
        interval_s=2,
        ctx=ctx,
        description=(
            f"the accepted refresh {accepted} is visible in DescribeInstanceRefreshes -- the "
            f"positive control, without which this check cannot tell a state gate from a "
            f"blanket refusal of AlarmSpecification"
        ),
    )
    assert accepted in seen, (
        f"the refresh accepted while the alarm was OK never appeared in "
        f"DescribeInstanceRefreshes: {seen!r}, expected {accepted!r}"
    )
    # Free the group: only one refresh may be active at a time, so the rejection below must
    # not be attributable to a concurrent refresh.
    asg.cancel_instance_refresh(AutoScalingGroupName=name)
    _poll(
        lambda: _refresh(ctx, name, accepted)["Status"],
        lambda s: s in _TERMINAL_STATUSES,
        timeout_s=_budget_s(ctx, 900),
        interval_s=2,
        ctx=ctx,
        description=f"the control refresh {accepted} reached a terminal status after Cancel",
    )
    before = _refresh_ids(ctx, name)

    # Break only the alarm's state.
    _force_alarm_state(ctx, alarm, name, "ALARM")
    code, message = _client_error(
        lambda: asg.start_instance_refresh(
            AutoScalingGroupName=name, Strategy="Rolling", Preferences=preferences
        ),
        what=(
            "StartInstanceRefresh with an AlarmSpecification naming an alarm that is in ALARM"
        ),
    )
    assert code == _REJECTION_CODE, (
        f"expected {_REJECTION_CODE!r} when the specified alarm is in ALARM, got "
        f"{code!r}: {message!r}"
    )
    # The refusal names an alarm as the reason, so it is told apart from a malformed request
    # or a missing permission.
    assert message == _REJECTION_MESSAGE, (
        f"expected {_REJECTION_MESSAGE!r} when the specified alarm is in ALARM, got "
        f"{code!r}: {message!r}"
    )

    # Repeated reads, so a refresh created late cannot slip past a single sample.
    for attempt in range(3):
        after = _refresh_ids(ctx, name)
        assert after == before, (
            f"the rejected StartInstanceRefresh still created a refresh (read "
            f"{attempt + 1} of 3): DescribeInstanceRefreshes went from {sorted(before)!r} to "
            f"{sorted(after)!r}"
        )
        time.sleep(2)
    active = _active_refresh_statuses(ctx, name)
    assert not active, (
        f"no refresh may be in flight after the rejection, but these are non-terminal: "
        f"{active!r}"
    )

    # With the alarm restored to OK, the identical call succeeds again.
    _force_alarm_state(ctx, alarm, name, "OK")
    restored = asg.start_instance_refresh(
        AutoScalingGroupName=name, Strategy="Rolling", Preferences=preferences
    )["InstanceRefreshId"]
    assert restored not in before, (
        f"the restored call must mint a NEW refresh id, but {restored!r} was already present "
        f"before the rejection: {sorted(before)!r}"
    )
    final = _poll(
        lambda: _refresh_ids(ctx, name),
        lambda ids: restored in ids,
        timeout_s=_budget_s(ctx, 120),
        interval_s=2,
        ctx=ctx,
        description=(
            f"after flipping the alarm back to OK the identical StartInstanceRefresh produced "
            f"a visible refresh {restored}"
        ),
    )
    assert restored in final, (
        f"the identical call after the restore did not produce a visible refresh: {final!r}, "
        f"expected to contain {restored!r}"
    )
    asg.cancel_instance_refresh(AutoScalingGroupName=name)
    _poll(
        lambda: _refresh(ctx, name, restored)["Status"],
        lambda s: s in _TERMINAL_STATUSES,
        timeout_s=_budget_s(ctx, 900),
        interval_s=2,
        ctx=ctx,
        description=f"the restored refresh {restored} reached a terminal status after Cancel",
    )


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


def _retry_delete(fn, what: str, *, attempts: int = 24, interval_s: float = 10.0) -> None:
    """Delete something that stays referenced while EC2 tears ENIs down."""
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception:  # noqa: BLE001 - still in use by a draining dependency
            time.sleep(interval_s)
    raise RuntimeError(f"{what} could not be deleted")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(fn, pred, *, timeout_s, interval_s=10, description="condition", ctx=None):
    """Poll fn() until pred() holds; RAISE with the last observed value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


def _al2023_ami(ctx) -> str:
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    value = ctx.client("ssm").get_parameter(Name=param)["Parameter"]["Value"]
    assert value.startswith("ami-"), f"{param} did not resolve to an AMI: {value!r}"
    return value


def _network(ctx, instance_type: str, want: int):
    """A dedicated VPC with `want` subnets, in AZs that offer instance_type.

    The account may have no default VPC, and a shared one can run out of IP addresses.
    """
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
        CidrBlock="10.221.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), f"vpc {vpc_id}")
    )

    subnet_ids = []
    for index, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.221.{index}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sn=subnet_id: _retry_delete(
                lambda: _delete_net(ec2, "delete_subnet", SubnetId=sn), f"subnet {sn}"
            )
        )
        subnet_ids.append(subnet_id)
    return vpc_id, azs, subnet_ids


def _launch_template(ctx, ami: str, *, instance_type: str = "t3.micro") -> str:
    """A launch template tagging both the instance and its volume at launch."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-as-lt-")
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
        lambda: _retry_delete(
            lambda: ec2.delete_launch_template(LaunchTemplateName=name),
            f"launch template {name}",
        )
    )
    return name


def _create_asg(ctx, lt_name: str, subnets, *, min_size: int, max_size: int, desired: int,
                lt_version: str = "$Latest", **kwargs) -> str:
    asg = ctx.client("autoscaling")
    name = ctx.unique_name("sim2real-behav-as-grp-")
    params = {
        "AutoScalingGroupName": name,
        "LaunchTemplate": {"LaunchTemplateName": lt_name, "Version": lt_version},
        "MinSize": min_size,
        "MaxSize": max_size,
        "DesiredCapacity": desired,
        "VPCZoneIdentifier": ",".join(subnets),
        "HealthCheckGracePeriod": 0,
        "DefaultCooldown": 0,
        "Tags": [
            {"Key": k, "Value": v, "PropagateAtLaunch": True} for k, v in _MANAGED_TAGS.items()
        ],
    }
    params.update(kwargs)
    if params.get("MixedInstancesPolicy") is not None:
        # A group declares a top-level launch template OR a mixed instances policy, never both.
        params.pop("LaunchTemplate", None)
    asg.create_auto_scaling_group(**params)

    def _drop():
        # A group left with capacity RELAUNCHES what you just deleted, and a group with
        # Terminate suspended cannot be drained at all -- so resume everything, drain to
        # zero, ForceDelete, then WAIT for the group to disappear before the subnets go.
        _unless_gone(lambda: asg.resume_processes(AutoScalingGroupName=name))
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
    """DescribeAutoScalingGroups for `name`, paginated."""
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


def _az_of(ctx, name: str, instance_id: str) -> str:
    for inst in _group(ctx, name)["Instances"]:
        if inst["InstanceId"] == instance_id:
            return inst["AvailabilityZone"]
    raise AssertionError(f"instance {instance_id!r} is not a member of group {name!r}")


def _count_by_az(ctx, name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for inst in _group(ctx, name)["Instances"]:
        if inst["LifecycleState"] == "InService":
            counts[inst["AvailabilityZone"]] = counts.get(inst["AvailabilityZone"], 0) + 1
    return counts


def _ec2_instance(ctx, instance_id: str) -> dict:
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=[instance_id]):
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst
    raise AssertionError(f"instance {instance_id!r} not found in DescribeInstances")


def _ec2_state(ctx, instance_id: str) -> str:
    return _ec2_instance(ctx, instance_id)["State"]["Name"]


def _launch_time(ctx, instance_id: str):
    return _ec2_instance(ctx, instance_id)["LaunchTime"]



def _client_error(fn, *, what: str) -> tuple[str, str]:
    """Run fn(), returning (code, message) of the ClientError it raised; raise if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code", ""), error.get("Message", "")
    raise AssertionError(f"{what} was ACCEPTED, but it must be refused")


def _put_alarm(ctx, alarm: str, group: str, treat_missing: str) -> None:
    """Create or update the alarm on a metric nothing publishes, so its evaluated state is set by
    ``treat_missing`` alone: notBreaching evaluates OK, breaching evaluates ALARM."""
    ctx.client("cloudwatch").put_metric_alarm(
        AlarmName=alarm,
        Namespace=f"SimParity/{CHECK}",
        MetricName="RefreshHealth",
        Dimensions=[{"Name": "AutoScalingGroupName", "Value": group}],
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData=treat_missing,
        Tags=_tags_kv(),
    )


def _force_alarm_state(ctx, alarm: str, group: str, state: str) -> None:
    """Drive the alarm to `state` and CONFIRM it there by reading CloudWatch back.

    The alarm's missing-data treatment is first set to evaluate to `state` too, so the alarm's
    next periodic evaluation keeps the forced state instead of reverting it. SetAlarmState is a
    request, not a fact; the state the gate under test consults is the one DescribeAlarms
    reports, so that is what gets asserted.
    """
    _put_alarm(ctx, alarm, group, "breaching" if state == "ALARM" else "notBreaching")
    ctx.client("cloudwatch").set_alarm_state(
        AlarmName=alarm,
        StateValue=state,
        StateReason=f"{CHECK}: forcing {state} to test the instance refresh admission gate",
    )
    observed = _poll(
        lambda: _alarm_state(ctx, alarm),
        lambda s: s == state,
        timeout_s=_budget_s(ctx, 180),
        interval_s=1,
        ctx=ctx,
        description=f"CloudWatch reports alarm {alarm} in state {state}",
    )
    assert observed == state, (
        f"the alarm did not settle in {state!r}: CloudWatch reports {observed!r}"
    )


def _alarm_state(ctx, alarm: str) -> str:
    alarms = ctx.client("cloudwatch").describe_alarms(AlarmNames=[alarm])["MetricAlarms"]
    assert alarms, f"alarm {alarm!r} not found in DescribeAlarms"
    return alarms[0]["StateValue"]


def _refresh(ctx, name: str, refresh_id: str) -> dict:
    asg = ctx.client("autoscaling")
    token = None
    while True:
        # botocore declares no paginator for DescribeInstanceRefreshes although the API takes
        # and returns NextToken.
        kw = {"AutoScalingGroupName": name, "InstanceRefreshIds": [refresh_id]}
        if token:
            kw["NextToken"] = token
        page = asg.describe_instance_refreshes(**kw)
        for record in page["InstanceRefreshes"]:
            if record["InstanceRefreshId"] == refresh_id:
                return record
        token = page.get("NextToken")
        if not token:
            break
    raise AssertionError(f"instance refresh {refresh_id!r} not found on group {name!r}")


def _all_refreshes(ctx, name: str) -> list[dict]:
    # botocore declares no paginator for DescribeInstanceRefreshes even though the API takes and
    # returns NextToken.
    records = []
    asg = ctx.client("autoscaling")
    token = None
    while True:
        kw = {"AutoScalingGroupName": name}
        if token:
            kw["NextToken"] = token
        page = asg.describe_instance_refreshes(**kw)
        records += page["InstanceRefreshes"]
        token = page.get("NextToken")
        if not token:
            break
    return records


def _refresh_ids(ctx, name: str) -> set[str]:
    return {r["InstanceRefreshId"] for r in _all_refreshes(ctx, name)}


def _active_refresh_statuses(ctx, name: str) -> dict[str, str]:
    return {
        r["InstanceRefreshId"]: r["Status"]
        for r in _all_refreshes(ctx, name)
        if r["Status"] not in _TERMINAL_STATUSES
    }


# Resources in a VPC delete asynchronously and leave their ENIs behind for a while, so subnet,
# security group and VPC deletes wait (bounded) for those ENIs and retry DependencyViolation.
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
