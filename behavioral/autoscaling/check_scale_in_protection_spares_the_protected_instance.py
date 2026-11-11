"""scale-in-protection-spares-the-protected-instance."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "scale-in-protection-spares-the-protected-instance"
GROUP = "capacity-management"
SERVICES = ["autoscaling"]


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:deploy",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """Scale-in picks the UNPROTECTED instance: the protected one is still running afterwards.
    SetInstanceProtection and SetDesiredCapacity return empty bodies, so only the surviving
    group membership shows which instance was terminated."""
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    _vpc, subnets = _usable_subnets(ctx, "t3.micro", want=2)
    lt_name = _launch_template(ctx, ami)
    name = _create_asg(ctx, lt_name, subnets, min_size=1, max_size=2, desired=2)

    both = _poll(
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == 2,
        timeout_s=900,
        description="setup: the group reached 2 InService instances",
    )
    protected_id, unprotected_id = both[0], both[1]

    asg.set_instance_protection(
        AutoScalingGroupName=name, InstanceIds=[protected_id], ProtectedFromScaleIn=True
    )
    # Clearing protection first means a teardown that has to drain the group is not fighting the
    # very flag this check set. Registered immediately after the call it undoes; LIFO puts it
    # ahead of the ASG force-delete registered earlier.
    ctx.on_cleanup(lambda: _unless_gone(lambda: asg.set_instance_protection(
        AutoScalingGroupName=name, InstanceIds=[protected_id], ProtectedFromScaleIn=False
    )))

    flags = _poll(
        lambda: _protection_flags(ctx, name),
        lambda f: f.get(protected_id) is True and f.get(unprotected_id) is False,
        timeout_s=180,
        interval_s=5,
        description=f"only {protected_id} reports ProtectedFromScaleIn",
    )
    assert flags[protected_id] is True and flags[unprotected_id] is False, (
        f"exactly one instance must be protected before the scale-in: {flags!r}"
    )

    asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1, HonorCooldown=False)

    survivors = _poll(
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=900,
        description="the group scaled in to exactly one InService instance",
    )
    survivor = survivors[0]
    assert survivor == protected_id, (
        f"scale-in terminated the protected instance: survivor {survivor!r}, "
        f"protected {protected_id!r}"
    )

    unprotected_state = _poll(
        lambda: _ec2_state(ctx, unprotected_id),
        lambda s: s in ("shutting-down", "terminated"),
        timeout_s=300,
        description=f"the unprotected instance {unprotected_id} was really terminated",
    )
    assert unprotected_state in ("shutting-down", "terminated"), (
        f"the unprotected instance was not terminated: {unprotected_state!r}"
    )
    survivor_state = _ec2_state(ctx, survivor)
    assert survivor_state == "running", (
        f"the protected instance is not running after the scale-in: {survivor_state!r}"
    )
    desired = _group(ctx, name)["DesiredCapacity"]
    assert desired == 1, f"the capacity change did not apply: {desired!r}"


# ===== helpers =====
_MANAGED_TAGS = {"sim2real": "as-depth", "sim2real:managed": "true"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _unless_gone(fn):
    """Run one teardown call: an already-gone group or instance is clean, a scaling activity still in
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
            if error["Code"] == "ValidationError" and ("not found" in message or "not part of" in message):
                return
            if error["Code"] not in ("ScalingActivityInProgress", "ResourceContention", "ResourceInUse") or (
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
        for _ in range(90):
            if not _describe_groups(ctx, name):
                return
            time.sleep(10)
        raise RuntimeError(f"auto scaling group {name} still present after ForceDelete")

    ctx.on_cleanup(_drop)
    return name


def _describe_groups(ctx, name: str) -> list:
    """Paginated: a filtered Describe can still return multiple pages."""
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


def _protection_flags(ctx, name: str) -> dict[str, bool]:
    """{instance-id: ProtectedFromScaleIn} for the group, paginated."""
    flags: dict[str, bool] = {}
    for page in ctx.client("autoscaling").get_paginator(
        "describe_auto_scaling_instances"
    ).paginate():
        for inst in page["AutoScalingInstances"]:
            if inst["AutoScalingGroupName"] == name:
                flags[inst["InstanceId"]] = inst["ProtectedFromScaleIn"]
    return flags


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
