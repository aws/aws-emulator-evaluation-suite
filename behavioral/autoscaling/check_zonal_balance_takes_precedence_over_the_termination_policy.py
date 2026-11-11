"""zonal-balance-takes-precedence-over-the-termination-policy."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "zonal-balance-takes-precedence-over-the-termination-policy"
GROUP = "instance-lifecycle"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Zonal balance outranks TerminationPolicies: with OldestInstance and a 2/1 split, scale-in
    terminates the older of the two fat-AZ instances, sparing the globally-oldest one in the thin AZ.
    """
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    _vpc, azs, subnets = _network(ctx, "t3.micro", want=2)
    az_thin, az_fat = azs[0], azs[1]
    sn_thin, sn_fat = subnets[0], subnets[1]
    lt_name = _launch_template(ctx, ami)

    # Stage 1: the globally-oldest instance is born alone in the THIN zone.
    name = _create_asg(
        ctx,
        lt_name,
        [sn_thin],
        min_size=0,
        max_size=3,
        desired=1,
        TerminationPolicies=["OldestInstance"],
    )
    oldest = _poll(
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=900,
        description="setup: the group reached 1 InService instance in the thin zone",
    )[0]
    assert _az_of(ctx, name, oldest) == az_thin, (
        f"setup: expected the first instance {oldest} in {az_thin}, "
        f"got {_az_of(ctx, name, oldest)}"
    )

    # AZRebalance is a PROACTIVE launch+terminate loop; suspending it is the only way to
    # grow the group inside one zone without AWS immediately evicting the thin-zone
    # instance whose subnet we are about to de-configure. It is resumed before the scale-in
    # so the behaviour under test is measured with every process running.
    asg.suspend_processes(AutoScalingGroupName=name, ScalingProcesses=["AZRebalance"])

    # Stage 2 and 3: two more instances, ONE AT A TIME so their LaunchTimes strictly order,
    # into the FAT zone only (it is the group's only configured subnet at this point).
    asg.update_auto_scaling_group(AutoScalingGroupName=name, VPCZoneIdentifier=sn_fat)
    fat_ids: list[str] = []
    for step in (2, 3):
        asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=step)
        ids = _poll(
            lambda step=step: _ids_in_state(ctx, name, "InService"),
            lambda ids, step=step: len(ids) == step,
            timeout_s=900,
            interval_s=15,
            description=f"setup: the group reached {step} InService instances",
        )
        new = [i for i in ids if i != oldest and i not in fat_ids]
        assert len(new) == 1, (
            f"setup: expected exactly 1 new instance at desired={step}, got {new!r} "
            f"(oldest={oldest!r}, already seen={fat_ids!r})"
        )
        assert _az_of(ctx, name, new[0]) == az_fat, (
            f"setup: expected the new instance {new[0]} in the fat zone {az_fat}, "
            f"got {_az_of(ctx, name, new[0])}"
        )
        fat_ids.append(new[0])
    fat_older, fat_newer = fat_ids
    assert _launch_time(ctx, fat_older) < _launch_time(ctx, fat_newer), (
        f"setup: the two fat-zone instances must be strictly ordered by LaunchTime, got "
        f"{fat_older}={_launch_time(ctx, fat_older)} vs "
        f"{fat_newer}={_launch_time(ctx, fat_newer)}"
    )
    assert _launch_time(ctx, oldest) < _launch_time(ctx, fat_older), (
        f"setup: {oldest} must be the globally oldest instance, but "
        f"{_launch_time(ctx, oldest)} is not before {_launch_time(ctx, fat_older)}"
    )

    # Re-enable the thin zone and resume every process. 2/1 across two zones is already the
    # best split for three instances, so nothing should move -- asserted, not assumed.
    asg.update_auto_scaling_group(
        AutoScalingGroupName=name, VPCZoneIdentifier=f"{sn_thin},{sn_fat}"
    )
    asg.resume_processes(AutoScalingGroupName=name, ScalingProcesses=["AZRebalance"])
    settled = _poll(
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: sorted(ids) == sorted([oldest, fat_older, fat_newer]),
        timeout_s=300,
        interval_s=10,
        description=(
            "setup: re-adding the thin subnet and resuming AZRebalance left all three "
            "instances in service (2/1 is already balanced)"
        ),
    )
    assert sorted(settled) == sorted([oldest, fat_older, fat_newer]), (
        f"setup: the membership changed while re-enabling the thin zone: {sorted(settled)!r}, "
        f"expected {sorted([oldest, fat_older, fat_newer])!r}"
    )
    by_az = _count_by_az(ctx, name)
    assert by_az == {az_fat: 2, az_thin: 1}, (
        f"setup: expected a 2/1 split with the fat zone {az_fat} holding 2, got {by_az!r}"
    )

    # The one act under test.
    asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=2)

    survivors = _poll(
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == 2,
        timeout_s=900,
        interval_s=15,
        description="the group scaled in from 3 to 2 InService instances",
    )
    assert sorted(survivors) == sorted([oldest, fat_newer]), (
        f"scale-in chose the wrong instance: survivors {sorted(survivors)!r}, expected "
        f"{sorted([oldest, fat_newer])!r}. Killing {oldest} means zonal balance was ignored "
        f"and OldestInstance was applied globally; killing {fat_newer} means the zone was "
        f"chosen but OldestInstance was not applied inside it."
    )

    # Terminal read at EC2 -- a different service and a different operation than the
    # SetDesiredCapacity that caused it, and the only place the kill is actually visible.
    dead = _poll(
        lambda: _ec2_state(ctx, fat_older),
        lambda s: s in ("shutting-down", "terminated"),
        timeout_s=600,
        description=f"the fat-zone oldest instance {fat_older} was really terminated in EC2",
    )
    assert dead in ("shutting-down", "terminated"), (
        f"the instance the group dropped was not terminated in EC2: {fat_older} is {dead!r}"
    )
    spared = _ec2_state(ctx, oldest)
    assert spared == "running", (
        f"the globally-oldest instance {oldest} in the thin zone must be spared, "
        f"but EC2 reports it as {spared!r}"
    )


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
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    value = ctx.client("ssm").get_parameter(Name=param)["Parameter"]["Value"]
    assert value.startswith("ami-"), f"{param} did not resolve to an AMI: {value!r}"
    return value


def _network(ctx, instance_type: str, want: int):
    """A DEDICATED VPC with `want` subnets, in AZs that really offer instance_type.

    A freshly provisioned account may have no default VPC at all, and borrowing an ambient
    one lets a concurrent run's IP exhaustion masquerade as a scaling failure.
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
    """Tag BOTH the instance and its volume AT LAUNCH, so the server-minted ids an ASG
    creates stay attributable to this check and reapable if teardown loses one."""
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
