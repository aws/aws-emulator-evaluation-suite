"""suspending-replace-unhealthy-withholds-the-replacement-until-it-is-resumed."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "suspending-replace-unhealthy-withholds-the-replacement-until-it-is-resumed"
GROUP = "capacity-management"
SERVICES = ["autoscaling"]


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:deploy",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A suspended ReplaceUnhealthy process withholds a replacement a control group performs:
    the control group's relaunch is the barrier that makes the subject's unchanged instance
    evidence, and resuming the process then performs the withheld replacement."""
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    _vpc, subnets = _usable_subnets(ctx, "t3.micro", want=2)
    lt_name = _launch_template(ctx, ami)
    control = _create_asg(
        ctx, lt_name, subnets, min_size=1, max_size=1, desired=1, HealthCheckType="EC2"
    )
    subject = _create_asg(
        ctx, lt_name, subnets, min_size=1, max_size=1, desired=1, HealthCheckType="EC2"
    )

    control_before = _poll(
        lambda: _ids_in_state(ctx, control, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=900,
        description="setup: the control group reached 1 InService instance",
    )[0]
    subject_before = _poll(
        lambda: _ids_in_state(ctx, subject, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=900,
        description="setup: the subject group reached 1 InService instance",
    )[0]
    assert control_before != subject_before, (
        f"the two groups must hold different instances: {control_before!r}"
    )

    # Break exactly one thing, on the subject only.
    asg.suspend_processes(AutoScalingGroupName=subject, ScalingProcesses=["ReplaceUnhealthy"])
    ctx.on_cleanup(lambda: _unless_gone(lambda: asg.resume_processes(
        AutoScalingGroupName=subject, ScalingProcesses=["ReplaceUnhealthy"]
    )))
    suspended = {p["ProcessName"] for p in _group(ctx, subject)["SuspendedProcesses"]}
    assert "ReplaceUnhealthy" in suspended, (
        f"the process was not recorded as suspended on the subject group: {sorted(suspended)!r}"
    )
    assert not _group(ctx, control)["SuspendedProcesses"], (
        f"the control group must have nothing suspended: "
        f"{_group(ctx, control)['SuspendedProcesses']!r}"
    )

    # One fan-out, same instant, so no propagation delta exists between the two groups.
    for instance_id in (control_before, subject_before):
        asg.set_instance_health(
            InstanceId=instance_id, HealthStatus="Unhealthy", ShouldRespectGracePeriod=False
        )
    subject_health = _poll(
        lambda: _health_of(ctx, subject, subject_before),
        lambda h: h == "Unhealthy",
        timeout_s=180,
        interval_s=5,
        description=f"the subject instance {subject_before} records HealthStatus Unhealthy",
    )
    assert subject_health == "Unhealthy", (
        f"the Unhealthy mark never landed on the subject instance, so withholding its replacement "
        f"is not evidence of anything: {subject_health!r}"
    )

    # The barrier: the control group really does the work the subject is suspended from.
    control_after = _poll(
        lambda: _ids_in_state(ctx, control, "InService"),
        lambda ids: len(ids) == 1 and ids[0] != control_before,
        timeout_s=1200,
        interval_s=15,
        description=f"the control group replaced its unhealthy instance {control_before}",
    )[0]
    assert control_after != control_before, (
        f"the control group did not replace its unhealthy instance, so the absence below is not "
        f"evidence: {control_after!r}"
    )
    subject_id_during_suspension = _ids_in_state(ctx, subject, "InService")
    assert subject_id_during_suspension == [subject_before], (
        f"the suspended group replaced its instance anyway: {subject_id_during_suspension!r}, "
        f"expected only {subject_before!r}"
    )
    assert _ec2_state(ctx, subject_before) == "running", (
        f"the suspended group's instance was terminated even though ReplaceUnhealthy is suspended: "
        f"{_ec2_state(ctx, subject_before)!r}"
    )

    # Repair the one broken thing: the withheld replacement must now happen.
    asg.resume_processes(AutoScalingGroupName=subject, ScalingProcesses=["ReplaceUnhealthy"])
    subject_after_resume = _poll(
        lambda: _ids_in_state(ctx, subject, "InService"),
        lambda ids: len(ids) == 1 and ids[0] != subject_before,
        timeout_s=1200,
        interval_s=15,
        description=f"resuming ReplaceUnhealthy replaced {subject_before}",
    )[0]
    assert subject_after_resume != subject_before, (
        f"resuming ReplaceUnhealthy did not replace the instance: {subject_after_resume!r}"
    )
    old_state = _poll(
        lambda: _ec2_state(ctx, subject_before),
        lambda s: s in ("shutting-down", "terminated"),
        timeout_s=600,
        description=f"the subject's original instance {subject_before} was really terminated",
    )
    assert old_state in ("shutting-down", "terminated"), (
        f"the subject's original instance was not terminated after the resume: {old_state!r}"
    )


# ===== helpers =====
_MANAGED_TAGS = {"sim2real": "as-depth", "sim2real:managed": "true"}


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
        # FIRST, then ForceDelete, then WAIT for the group to disappear. Resuming every suspended
        # process first (registered later, so LIFO runs it before this) matters here: a group with
        # Terminate suspended cannot be drained at all.
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


def _health_of(ctx, name: str, instance_id: str) -> str:
    for inst in _group(ctx, name)["Instances"]:
        if inst["InstanceId"] == instance_id:
            return inst["HealthStatus"]
    return "absent"


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
