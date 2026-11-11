"""scheduled-action-cron-is-interpreted-in-its-declared-time-zone."""
from __future__ import annotations

import datetime as dt
import time
import zoneinfo

from behavioral_harness import tags

CHECK = "scheduled-action-cron-is-interpreted-in-its-declared-time-zone"
GROUP = "scheduled-actions"
SERVICES = ["autoscaling"]

# How far ahead the target minute is placed, and how long past it the poll will wait.
LEAD_S = 90
GRACE_S = 180


# timing:real-time — schedule: 90 s https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-scheduled-scaling.html
@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """The same cron fires at different instants per declared IANA TimeZone: the zone-aware group
    moves at its local minute while a UTC twin stays still, and a correctly timed UTC action then
    moves the twin, proving it runs scheduled actions at all.

    Reference: https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-scheduled-scaling.html
    """
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    _vpc, _azs, subnets = _network(ctx, "t3.micro", want=1)
    lt_name = _launch_template(ctx, ami)
    # Launch is suspended: a scheduled action still moves DesiredCapacity, with no instance billed.
    subject = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=1, desired=0)
    control = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=1, desired=0)
    for name in (subject, control):
        asg.suspend_processes(AutoScalingGroupName=name, ScalingProcesses=["Launch"])

    zone, target_utc, cron = _zone_and_cron(offset_at_least_s=3600)
    utc_reading = _utc_reading_of(cron, target_utc)
    skew = abs((utc_reading - target_utc).total_seconds())
    assert skew >= 3600, (
        f"setup: the chosen zone {zone} must make the same cron {cron!r} denote an instant at "
        f"least 3600s from the target, got {skew}s (target={target_utc.isoformat()}, "
        f"UTC reading={utc_reading.isoformat()})"
    )

    action = ctx.unique_name("sim2real-sched-tz-")
    asg.put_scheduled_update_group_action(
        AutoScalingGroupName=subject,
        ScheduledActionName=action,
        Recurrence=cron,
        TimeZone=zone,
        DesiredCapacity=1,
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: asg.delete_scheduled_action(
        AutoScalingGroupName=subject, ScheduledActionName=action)))
    asg.put_scheduled_update_group_action(
        AutoScalingGroupName=control,
        ScheduledActionName=action,
        Recurrence=cron,
        TimeZone="UTC",
        DesiredCapacity=1,
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: asg.delete_scheduled_action(
        AutoScalingGroupName=control, ScheduledActionName=action)))

    for name, expected_zone in ((subject, zone), (control, "UTC")):
        recorded = _scheduled_action(ctx, name, action)
        assert recorded["Recurrence"] == cron, (
            f"{name} did not record the cron verbatim: expected {cron!r}, got "
            f"{recorded.get('Recurrence')!r}"
        )
        assert recorded.get("TimeZone") == expected_zone, (
            f"{name} did not record the declared time zone: expected {expected_zone!r}, got "
            f"{recorded.get('TimeZone')!r}"
        )

    # The subject must move at its zone-local minute.
    deadline_s = max(0.0, (target_utc - _now()).total_seconds()) + GRACE_S
    moved = _poll(
        ctx,
        lambda: _group(ctx, subject)["DesiredCapacity"],
        lambda d: d == 1,
        timeout_s=deadline_s,
        interval_s=2,
        description=(
            f"the scheduled action interpreted in {zone} moved the subject group's "
            f"DesiredCapacity to 1 at or after {target_utc.isoformat()}"
        ),
    )
    assert moved == 1, (
        f"the zone-aware scheduled action did not fire: subject DesiredCapacity is {moved!r}, "
        f"expected 1"
    )

    # The twin's identical cron, read as UTC, denotes an instant at least an hour away.
    control_desired = _group(ctx, control)["DesiredCapacity"]
    assert control_desired == 0, (
        f"the identical cron read as UTC must not have fired yet ({skew}s away), but the "
        f"control group's DesiredCapacity is {control_desired!r}, expected 0. A target that "
        f"ignores TimeZone fires both groups together."
    )
    control_activities = _activity_causes(ctx, control)
    assert not control_activities, (
        f"the control group must have recorded no scaling activity yet, got "
        f"{control_activities!r}"
    )

    # Without this leg, a group that never runs scheduled actions would pass the stillness assert.
    proof_zone, proof_target, proof_cron = _zone_and_cron(offset_at_least_s=0, zone="UTC")
    proof_action = ctx.unique_name("sim2real-sched-utc-")
    asg.put_scheduled_update_group_action(
        AutoScalingGroupName=control,
        ScheduledActionName=proof_action,
        Recurrence=proof_cron,
        TimeZone=proof_zone,
        DesiredCapacity=1,
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: asg.delete_scheduled_action(
        AutoScalingGroupName=control, ScheduledActionName=proof_action)))
    proof_deadline_s = max(0.0, (proof_target - _now()).total_seconds()) + GRACE_S
    control_moved = _poll(
        ctx,
        lambda: _group(ctx, control)["DesiredCapacity"],
        lambda d: d == 1,
        timeout_s=proof_deadline_s,
        interval_s=2,
        description=(
            "the control group runs scheduled actions at all: a UTC action timed for "
            f"{proof_target.isoformat()} moved its DesiredCapacity to 1"
        ),
    )
    assert control_moved == 1, (
        f"the control group never ran ANY scheduled action, so its earlier stillness was not "
        f"evidence about time zones: DesiredCapacity is {control_moved!r}, expected 1"
    )

    # Both groups recorded a scaling Activity for the scheduled change.
    for name in (subject, control):
        causes = _poll(
            ctx,
            lambda name=name: _activity_causes(ctx, name),
            lambda causes: len(causes) >= 1,
            timeout_s=300,
            interval_s=2,
            description=f"{name} recorded a scaling Activity for its scheduled capacity change",
        )
        assert causes, (
            f"{name} moved its DesiredCapacity with no Activity record, so nothing on the "
            f"server side accounts for the change: {causes!r}"
        )


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _zone_and_cron(*, offset_at_least_s: int, zone: str | None = None):
    """Pick a zone and build a 5-field cron for LEAD_S from now, expressed in that zone.

    Candidates span positive, negative and half-hour offsets; the tz database supplies DST offsets.
    """
    target = (_now() + dt.timedelta(seconds=LEAD_S)).replace(second=0, microsecond=0)
    candidates = [zone] if zone else [
        "Asia/Kolkata", "Asia/Tokyo", "Pacific/Auckland", "America/Los_Angeles",
        "Asia/Katmandu", "Etc/GMT+9",
    ]
    for name in candidates:
        tz = zoneinfo.ZoneInfo(name)
        offset = target.astimezone(tz).utcoffset()
        assert offset is not None, f"the tz database returned no offset for {name!r}"
        if abs(offset.total_seconds()) >= offset_at_least_s:
            local = target.astimezone(tz)
            return name, target, f"{local.minute} {local.hour} * * *"
    raise AssertionError(
        f"no candidate zone had an offset of at least {offset_at_least_s}s at "
        f"{target.isoformat()}: {candidates!r}"
    )


def _utc_reading_of(cron: str, target: dt.datetime) -> dt.datetime:
    """The next instant on or after `target` that the same cron denotes when read as UTC."""
    minute, hour = (int(field) for field in cron.split()[:2])
    candidate = target.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate < target:
        candidate += dt.timedelta(days=1)
    return candidate


def _scheduled_action(ctx, group: str, action: str) -> dict:
    paginator = ctx.client("autoscaling").get_paginator("describe_scheduled_actions")
    for page in paginator.paginate(
        AutoScalingGroupName=group, ScheduledActionNames=[action]
    ):
        for record in page["ScheduledUpdateGroupActions"]:
            if record["ScheduledActionName"] == action:
                return record
    raise AssertionError(f"scheduled action {action!r} not found on group {group!r}")


def _activity_causes(ctx, group: str) -> list[str]:
    causes = []
    paginator = ctx.client("autoscaling").get_paginator("describe_scaling_activities")
    for page in paginator.paginate(AutoScalingGroupName=group):
        for activity in page["Activities"]:
            causes.append(activity["Cause"])
    return causes


_MANAGED_TAGS = {"sim2real": CHECK, "sim2real:managed": "true"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _unless_gone(fn):
    """Run one teardown call: an already-gone group is clean, a scaling activity still in
    progress is retried every 2 s for 60 s, and every other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    while True:
        try:
            fn()
            return
        except ClientError as err:
            error = err.response["Error"]
            message = error.get("Message", "")
            if error["Code"] == "ValidationError" and "not found" in message:
                return
            if error["Code"] not in ("ScalingActivityInProgress", "ResourceContention", "ResourceInUse") or (
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


def _poll(ctx, fn, pred, *, timeout_s, interval_s=2, description="condition"):
    """Poll fn() until pred() holds; RAISE with the last observed value on timeout."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
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


def _network(ctx, instance_type: str, want: int):
    """A dedicated VPC with `want` subnets, in AZs that really offer instance_type.

    An account may lack a default VPC, and a shared one's IP exhaustion mimics a scaling failure.
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
    """A launch template that tags the instance and its volume at launch."""
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
        # A group with capacity relaunches, and one with Terminate suspended cannot drain: resume,
        # drain to zero, ForceDelete, then wait for it to disappear before the subnets go.
        _unless_gone(lambda: asg.resume_processes(AutoScalingGroupName=name))
        _unless_gone(lambda: asg.update_auto_scaling_group(
            AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0))
        _unless_gone(lambda: asg.delete_auto_scaling_group(
            AutoScalingGroupName=name, ForceDelete=True))
        for _ in range(90):
            if not _describe_groups(ctx, name):
                return
            time.sleep(10)
        raise RuntimeError(f"auto scaling group {name} still present after ForceDelete")

    ctx.on_cleanup(_drop)
    return name


def _describe_groups(ctx, name: str) -> list:
    """The groups matching name, across all pages."""
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


# Load balancers, endpoints and instances delete asynchronously, leaving ENIs that make an
# immediate DeleteSubnet/DeleteVpc fail with DependencyViolation; wait for them, bounded.
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
        _time.sleep(10)
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
        _time.sleep(10)


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
