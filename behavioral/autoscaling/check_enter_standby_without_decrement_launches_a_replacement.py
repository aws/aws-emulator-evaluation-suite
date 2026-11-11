"""enter-standby-without-decrement-launches-a-replacement."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "enter-standby-without-decrement-launches-a-replacement"
GROUP = "instance-lifecycle"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ShouldDecrementDesiredCapacity=False makes the group LAUNCH a replacement while the
    standby instance keeps running; a twin group that decrements launches nothing."""
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    _vpc, _azs, subnets = _network(ctx, "t3.micro", want=1)
    lt_name = _launch_template(ctx, ami)
    # MinSize=0 so the CONTROL group is permitted to decrement; MaxSize=2 so the SUBJECT group
    # is permitted to hold its standby instance and a replacement at the same time.
    control = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=2, desired=1)
    subject = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=2, desired=1)

    control_before = _poll(
        lambda: _ids_in_state(ctx, control, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=900,
        interval_s=15,
        description="setup: the control group reached 1 InService instance",
    )[0]
    subject_before = _poll(
        lambda: _ids_in_state(ctx, subject, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=900,
        interval_s=15,
        description="setup: the subject group reached 1 InService instance",
    )[0]
    assert control_before != subject_before, (
        f"the two groups must hold different instances, both report {control_before!r}"
    )

    # One fan-out, same instant, differing in exactly one flag.
    asg.enter_standby(
        AutoScalingGroupName=control,
        InstanceIds=[control_before],
        ShouldDecrementDesiredCapacity=True,
    )
    asg.enter_standby(
        AutoScalingGroupName=subject,
        InstanceIds=[subject_before],
        ShouldDecrementDesiredCapacity=False,
    )
    for name, instance_id in ((control, control_before), (subject, subject_before)):
        state = _poll(
            lambda name=name, instance_id=instance_id: _state_of(ctx, name, instance_id),
            lambda s: s == "Standby",
            timeout_s=300,
            interval_s=10,
            description=f"{instance_id} reached LifecycleState Standby in {name}",
        )
        assert state == "Standby", (
            f"{instance_id} never reached Standby in {name}: LifecycleState is {state!r}"
        )

    # The barrier: the decrementing twin moves its capacity down and launches NOTHING.
    control_desired = _poll(
        lambda: _group(ctx, control)["DesiredCapacity"],
        lambda d: d == 0,
        timeout_s=300,
        interval_s=10,
        description="the control group's DesiredCapacity was decremented to 0",
    )
    assert control_desired == 0, (
        f"the control group's DesiredCapacity must be decremented to 0, got {control_desired!r}"
    )
    control_members = sorted(_lifecycle_states(ctx, control))
    assert control_members == [control_before], (
        f"the decrementing group must launch no replacement: members {control_members!r}, "
        f"expected only the standby instance {[control_before]!r}"
    )

    # The subject holds its capacity and launches the replacement the twin did not.
    replacement = _poll(
        lambda: [i for i in _ids_in_state(ctx, subject, "InService") if i != subject_before],
        lambda ids: len(ids) == 1,
        timeout_s=900,
        interval_s=15,
        description=(
            "the subject group launched a replacement for the instance it put on standby "
            "without decrementing"
        ),
    )[0]
    assert replacement != subject_before, (
        f"the replacement must be a new instance, got the standby instance itself "
        f"{replacement!r}"
    )
    subject_desired = _group(ctx, subject)["DesiredCapacity"]
    assert subject_desired == 1, (
        f"the subject group's DesiredCapacity must be untouched by a non-decrementing "
        f"EnterStandby: expected 1, got {subject_desired!r}"
    )
    subject_members = _lifecycle_states(ctx, subject)
    assert sorted(subject_members) == sorted([subject_before, replacement]), (
        f"the subject group must hold BOTH the standby instance and its replacement -- two "
        f"members for a desired capacity of 1: got {sorted(subject_members)!r}, expected "
        f"{sorted([subject_before, replacement])!r}"
    )

    # Terminal read at EC2: Standby is an ASG state, not an EC2 stop, and the replacement is
    # a real machine rather than a bookkeeping row.
    standby_ec2 = _ec2_state(ctx, subject_before)
    assert standby_ec2 == "running", (
        f"the standby instance {subject_before} must keep running in EC2, got {standby_ec2!r}"
    )
    replacement_ec2 = _poll(
        lambda: _ec2_state(ctx, replacement),
        lambda s: s == "running",
        timeout_s=600,
        interval_s=15,
        description=f"the replacement instance {replacement} is really running in EC2",
    )
    assert replacement_ec2 == "running", (
        f"the replacement instance {replacement} is not a real running machine: EC2 reports "
        f"{replacement_ec2!r}"
    )

    # Close the loop: bring the held instance back and demand the group stay self-consistent.
    asg.exit_standby(AutoScalingGroupName=subject, InstanceIds=[subject_before])
    returned = _poll(
        lambda: _state_of(ctx, subject, subject_before),
        lambda s: s == "InService",
        timeout_s=600,
        interval_s=15,
        description=f"ExitStandby returned {subject_before} to InService",
    )
    assert returned == "InService", (
        f"ExitStandby did not return {subject_before} to service: LifecycleState is "
        f"{returned!r}"
    )
    settled = _poll(
        lambda: (
            _group(ctx, subject)["DesiredCapacity"],
            len(_ids_in_state(ctx, subject, "InService")),
        ),
        lambda pair: pair == (2, 2),
        timeout_s=600,
        interval_s=15,
        description=(
            "after ExitStandby the group's own DesiredCapacity matches the number of instances "
            "it is holding InService"
        ),
    )
    assert settled[0] == settled[1] == 2, (
        f"after ExitStandby the group must account for both instances: DesiredCapacity "
        f"{settled[0]!r} vs InService count {settled[1]!r}, expected 2 and 2"
    )


_MANAGED_TAGS = {"sim2real": CHECK, "sim2real:managed": "true"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step only)."""
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown
        pass


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
        _swallow(lambda: asg.resume_processes(AutoScalingGroupName=name))
        _swallow(lambda: asg.update_auto_scaling_group(
            AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0))
        _swallow(lambda: asg.delete_auto_scaling_group(
            AutoScalingGroupName=name, ForceDelete=True))
        for _ in range(90):
            if not _describe_groups(ctx, name):
                return
            time.sleep(10)
        raise RuntimeError(f"auto scaling group {name} still present after ForceDelete")

    ctx.on_cleanup(_drop)
    return name


def _describe_groups(ctx, name: str) -> list:
    """Paginated: a filtered Describe still returns pages."""
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



def _lifecycle_states(ctx, name: str) -> dict[str, str]:
    """id -> LifecycleState for EVERY instance the group owns.

    DescribeAutoScalingInstances is used rather than DescribeAutoScalingGroups because it is a
    DIFFERENT operation from the EnterStandby that caused the move, and because it is the read
    that carries Standby and Warmed:* states uniformly.
    """
    states: dict[str, str] = {}
    paginator = ctx.client("autoscaling").get_paginator("describe_auto_scaling_instances")
    for page in paginator.paginate():
        for inst in page["AutoScalingInstances"]:
            if inst["AutoScalingGroupName"] == name:
                states[inst["InstanceId"]] = inst["LifecycleState"]
    return states


def _state_of(ctx, name: str, instance_id: str) -> str:
    return _lifecycle_states(ctx, name).get(instance_id, "absent")


# A resource in this VPC deletes asynchronously: its ENIs stay in the subnet / security group for a
# while, so DeleteSubnet / DeleteSecurityGroup / DeleteVpc answer DependencyViolation. Wait (bounded)
# for those ENIs to go, retry DependencyViolation in the same window, then raise naming what is left.
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
