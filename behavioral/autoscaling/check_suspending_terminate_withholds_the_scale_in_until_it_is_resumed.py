"""suspending-terminate-withholds-the-scale-in-until-it-is-resumed."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "suspending-terminate-withholds-the-scale-in-until-it-is-resumed"
GROUP = "capacity-management"
SERVICES = ["autoscaling"]


@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A suspended Terminate process withholds a scale-in that a control group performs: the
    control group's termination is the barrier that makes the subject's surviving instances
    evidence, and resuming Terminate then performs the withheld scale-in."""
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    _vpc, _azs, subnets = _network(ctx, "t3.micro", want=1)
    lt_name = _launch_template(ctx, ami)
    control = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=2, desired=2)
    subject = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=2, desired=2)

    control_before = _poll(
        lambda: _ids_in_state(ctx, control, "InService"),
        lambda ids: len(ids) == 2,
        timeout_s=900,
        interval_s=15,
        description="setup: the control group reached 2 InService instances",
    )
    subject_before = _poll(
        lambda: _ids_in_state(ctx, subject, "InService"),
        lambda ids: len(ids) == 2,
        timeout_s=900,
        interval_s=15,
        description="setup: the subject group reached 2 InService instances",
    )
    assert not set(control_before) & set(subject_before), (
        f"the two groups must hold different instances: control={control_before!r}, "
        f"subject={subject_before!r}"
    )

    # Break exactly one thing, on the subject only.
    asg.suspend_processes(AutoScalingGroupName=subject, ScalingProcesses=["Terminate"])
    ctx.on_cleanup(lambda: _unless_gone(lambda: asg.resume_processes(
        AutoScalingGroupName=subject, ScalingProcesses=["Terminate"]
    )))
    suspended = {p["ProcessName"] for p in _group(ctx, subject)["SuspendedProcesses"]}
    assert suspended == {"Terminate"}, (
        f"the subject group must have exactly Terminate suspended, got {sorted(suspended)!r}"
    )
    control_suspended = _group(ctx, control)["SuspendedProcesses"]
    assert not control_suspended, (
        f"the control group must have nothing suspended, got {control_suspended!r}"
    )

    # One fan-out, same instant, so no propagation delta exists between the two groups.
    for name in (control, subject):
        asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1)

    # The intent is recorded on BOTH groups: suspension withholds the act, not the field.
    for name in (control, subject):
        desired = _poll(
            lambda name=name: _group(ctx, name)["DesiredCapacity"],
            lambda d: d == 1,
            timeout_s=120,
            interval_s=5,
            description=f"{name} recorded DesiredCapacity=1",
        )
        assert desired == 1, (
            f"{name} did not record the requested DesiredCapacity: expected 1, got {desired!r}"
        )

    # The barrier: the control group really does the work the subject is suspended from.
    control_after = _poll(
        lambda: _ids_in_state(ctx, control, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=900,
        interval_s=15,
        description="the control group scaled in from 2 InService instances to 1",
    )
    assert len(control_after) == 1, (
        f"the control group did not scale in, so the absence below is not evidence: "
        f"{control_after!r}"
    )
    control_dropped = (set(control_before) - set(control_after)).pop()
    control_dead = _poll(
        lambda: _ec2_state(ctx, control_dropped),
        lambda s: s in ("shutting-down", "terminated"),
        timeout_s=600,
        description=f"the control group really terminated {control_dropped} in EC2",
    )
    assert control_dead in ("shutting-down", "terminated"), (
        f"the control group dropped {control_dropped} from the group but EC2 still reports "
        f"it as {control_dead!r} -- the barrier is not established"
    )

    # The withholding, measured at the same instant the barrier is proven.
    still_there = _ids_in_state(ctx, subject, "InService")
    assert sorted(still_there) == sorted(subject_before), (
        f"the group with Terminate suspended scaled in anyway: InService {sorted(still_there)!r}, "
        f"expected both original instances {sorted(subject_before)!r}"
    )
    for instance_id in subject_before:
        state = _ec2_state(ctx, instance_id)
        assert state == "running", (
            f"the suspended group's instance {instance_id} was terminated even though "
            f"Terminate is suspended: EC2 reports {state!r}, expected 'running'"
        )

    # Repair the one broken thing: the withheld termination must now happen, with no further
    # capacity call.
    asg.resume_processes(AutoScalingGroupName=subject, ScalingProcesses=["Terminate"])
    subject_after = _poll(
        lambda: _ids_in_state(ctx, subject, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=1200,
        interval_s=15,
        description="resuming Terminate performed the withheld scale-in",
    )
    assert len(subject_after) == 1, (
        f"resuming Terminate did not perform the withheld scale-in: {subject_after!r}, "
        f"expected exactly 1 InService instance"
    )
    subject_dropped = (set(subject_before) - set(subject_after)).pop()
    subject_dead = _poll(
        lambda: _ec2_state(ctx, subject_dropped),
        lambda s: s in ("shutting-down", "terminated"),
        timeout_s=600,
        description=f"the withheld instance {subject_dropped} was really terminated in EC2",
    )
    assert subject_dead in ("shutting-down", "terminated"), (
        f"the subject dropped {subject_dropped} from the group after the resume, but EC2 "
        f"reports it as {subject_dead!r}, expected shutting-down or terminated"
    )
    survivor_state = _ec2_state(ctx, subject_after[0])
    assert survivor_state == "running", (
        f"the surviving instance {subject_after[0]} must still be running after the resumed "
        f"scale-in, but EC2 reports {survivor_state!r}"
    )


# ===== helpers =====
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
        for _ in range(90):
            if not _describe_groups(ctx, name):
                return
            time.sleep(10)
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


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes: an asynchronous delete
# in this VPC leaves its ENIs behind briefly, so DeleteSubnet / DeleteVpc retries DependencyViolation
# within one shared window, then raises naming the ENIs still attached.
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
