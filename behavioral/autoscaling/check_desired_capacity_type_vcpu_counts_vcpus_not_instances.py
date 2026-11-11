"""desired-capacity-type-vcpu-counts-vcpus-not-instances."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "desired-capacity-type-vcpu-counts-vcpus-not-instances"
GROUP = "capacity-management"
SERVICES = ["autoscaling"]

# A pool whose members all have exactly 2 vCPUs, so the arithmetic below has one answer. The
# per-instance vCPU count is still READ FROM EC2 rather than assumed from this list.
ALLOWED_TYPES = ["t3.small", "t3a.small", "t2.small", "c5.large", "c6i.large", "m6i.large"]


@tags("axis:happy-path", "cap:c4", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With DesiredCapacityType="vcpu", DesiredCapacity is a vCPU budget: the group launches
    DesiredCapacity/vCPUs-per-instance machines (vCPUs read from EC2), not DesiredCapacity."""

    ami = _al2023_ami(ctx)
    _vpc, azs, subnets = _network(ctx, "t3.small", want=1)
    lt_name = _launch_template(ctx, ami, instance_type="t3.small")
    # Narrow the candidate pool to what this AZ actually offers, read from EC2. Handing
    # attribute-based selection a type the zone does not sell turns a capacity-unit question
    # into an insufficient-capacity failure.
    allowed = _types_offered_in(ctx, azs[0], ALLOWED_TYPES)
    assert len(allowed) >= 1, (
        f"none of the 2-vCPU candidate types {ALLOWED_TYPES!r} are offered in {azs[0]}"
    )

    desired_vcpus = 4
    name = _create_asg(
        ctx,
        lt_name,
        subnets,
        min_size=0,
        max_size=16,
        desired=desired_vcpus,
        DesiredCapacityType="vcpu",
        MixedInstancesPolicy={
            "LaunchTemplate": {
                "LaunchTemplateSpecification": {
                    "LaunchTemplateName": lt_name,
                    "Version": "$Latest",
                },
                "Overrides": [
                    {
                        "InstanceRequirements": {
                            "VCpuCount": {"Min": 2, "Max": 2},
                            "MemoryMiB": {"Min": 1024},
                            "BurstablePerformance": "included",
                            "AllowedInstanceTypes": allowed,
                        }
                    }
                ],
            },
            # All On-Demand: a Spot shortfall would look like a capacity-unit bug.
            "InstancesDistribution": {
                "OnDemandBaseCapacity": desired_vcpus,
                "OnDemandPercentageAboveBaseCapacity": 100,
            },
        },
    )

    group = _group(ctx, name)
    assert group.get("DesiredCapacityType") == "vcpu", (
        f"the group did not record the capacity unit: expected 'vcpu', got "
        f"{group.get('DesiredCapacityType')!r}"
    )
    assert group["DesiredCapacity"] == desired_vcpus, (
        f"the group did not record the vCPU budget: expected {desired_vcpus}, got "
        f"{group['DesiredCapacity']!r}"
    )

    # Derive the expected instance count from EC2's own catalogue AFTER seeing which type the
    # attribute-based selector picked -- so this check follows the target rather than a guess.
    served = _poll(
        ctx,
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) >= 1 and _vcpu_sum(ctx, name, ids) == desired_vcpus,
        timeout_s=1200,
        interval_s=2,
        description=(
            f"the group's InService instances summed to exactly {desired_vcpus} vCPUs, the "
            f"vCPU budget it was given"
        ),
    )
    per_instance = {
        instance_id: _vcpus_of(ctx, _instance_type_in_group(ctx, name, instance_id))
        for instance_id in served
    }
    for instance_id, vcpus in per_instance.items():
        assert vcpus == 2, (
            f"the InstanceRequirements demanded exactly 2 vCPUs, but EC2 reports "
            f"{instance_id} ({_instance_type_in_group(ctx, name, instance_id)}) as having "
            f"{vcpus}"
        )
    total = sum(per_instance.values())
    assert total == desired_vcpus, (
        f"the launched fleet does not match the vCPU budget: {per_instance!r} sums to {total}, "
        f"expected {desired_vcpus}"
    )
    expected_count = desired_vcpus // 2
    assert len(served) == expected_count, (
        f"expected {expected_count} instances of 2 vCPUs each for a {desired_vcpus}-vCPU "
        f"budget, got {len(served)}: {served!r}"
    )
    assert len(served) != desired_vcpus, (
        f"the group launched {len(served)} instances for DesiredCapacity={desired_vcpus} with "
        f"DesiredCapacityType='vcpu' -- it is counting instances, not vCPUs"
    )

    # Three consecutive reads must agree, so the match above is the settled
    # state rather than a moment on the way to overshooting the budget.
    for attempt in range(3):
        later = _ids_in_state(ctx, name, "InService")
        assert sorted(later) == sorted(served), (
            f"the fleet is still moving on read {attempt + 1} of 3: {sorted(later)!r}, "
            f"expected the settled set {sorted(served)!r}"
        )
        time.sleep(2)

    # Terminal read at EC2, through a different operation and a different service than the
    # CreateAutoScalingGroup that caused the launches.
    for instance_id in served:
        state = _ec2_state(ctx, instance_id)
        assert state == "running", (
            f"instance {instance_id} counted toward the vCPU budget but EC2 reports it as "
            f"{state!r}, expected 'running'"
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



_VCPU_CACHE: dict[str, int] = {}


def _types_offered_in(ctx, az: str, candidates: list[str]) -> list[str]:
    """Which of `candidates` this AZ actually offers, read from EC2."""
    offered = {
        o["InstanceType"]
        for o in ctx.client("ec2").describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[
                {"Name": "location", "Values": [az]},
                {"Name": "instance-type", "Values": candidates},
            ],
        )["InstanceTypeOfferings"]
    }
    return [t for t in candidates if t in offered]


def _vcpus_of(ctx, instance_type: str) -> int:
    """EC2's OWN vCPU count for the type -- the derivation source for the capacity arithmetic."""
    if instance_type not in _VCPU_CACHE:
        infos = ctx.client("ec2").describe_instance_types(
            InstanceTypes=[instance_type]
        )["InstanceTypes"]
        assert infos, f"DescribeInstanceTypes returned nothing for {instance_type!r}"
        _VCPU_CACHE[instance_type] = infos[0]["VCpuInfo"]["DefaultVCpus"]
    return _VCPU_CACHE[instance_type]


def _instance_type_in_group(ctx, name: str, instance_id: str) -> str:
    for inst in _group(ctx, name)["Instances"]:
        if inst["InstanceId"] == instance_id:
            return inst["InstanceType"]
    raise AssertionError(f"instance {instance_id!r} is not a member of group {name!r}")


def _vcpu_sum(ctx, name: str, instance_ids: list[str]) -> int:
    return sum(
        _vcpus_of(ctx, _instance_type_in_group(ctx, name, instance_id))
        for instance_id in instance_ids
    )


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
