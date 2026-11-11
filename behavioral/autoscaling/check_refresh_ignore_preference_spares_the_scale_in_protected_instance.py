"""refresh-ignore-preference-spares-the-scale-in-protected-instance."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "refresh-ignore-preference-spares-the-scale-in-protected-instance"
GROUP = "instance-refresh"
SERVICES = ["autoscaling"]

_FAILED_STATUSES = ("Failed", "Cancelled", "RollbackFailed", "RollbackSuccessful")


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An instance refresh with ScaleInProtectedInstances="Ignore" leaves the protected
    instance untouched and still succeeds; the twin refresh with "Refresh" replaces it, which
    shows the surviving instance is a consequence of "Ignore"."""
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    _vpc, _azs, subnets = _network(ctx, "t3.micro", want=1)
    lt_name = _launch_template(ctx, ami)
    # MaxSize=4 leaves head-room for the surge-before-terminate shape below; MinSize=0 keeps
    # the group's own bounds out of the refresh engine's way.
    control = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=4, desired=2)
    subject = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=4, desired=2)

    protected: dict[str, str] = {}
    unprotected: dict[str, str] = {}
    for name in (control, subject):
        ids = _poll(
            lambda name=name: _ids_in_state(ctx, name, "InService"),
            lambda ids: len(ids) == 2,
            timeout_s=900,
            interval_s=15,
            description=f"setup: {name} reached 2 InService instances",
        )
        protected[name], unprotected[name] = ids[0], ids[1]
        asg.set_instance_protection(
            AutoScalingGroupName=name,
            InstanceIds=[ids[0]],
            ProtectedFromScaleIn=True,
        )
    for name in (control, subject):
        flags = _protection_flags(ctx, name)
        assert flags == {protected[name]: True, unprotected[name]: False}, (
            f"setup: {name} must have exactly one scale-in-protected instance "
            f"({protected[name]}), got {flags!r}"
        )

    # Break exactly one thing: the preference, on the subject only.
    base_preferences = {
        "MinHealthyPercentage": 100,
        "MaxHealthyPercentage": 200,
        "InstanceWarmup": 0,
        "SkipMatching": False,
    }
    refresh_ids = {}
    for name, preference in ((control, "Refresh"), (subject, "Ignore")):
        refresh_ids[name] = asg.start_instance_refresh(
            AutoScalingGroupName=name,
            Strategy="Rolling",
            Preferences={**base_preferences, "ScaleInProtectedInstances": preference},
        )["InstanceRefreshId"]

    # The barrier: the control refresh really replaces the PROTECTED instance.
    control_status = _await_refresh(
        ctx, control, refresh_ids[control], timeout_s=1800,
        description="the control refresh (ScaleInProtectedInstances=Refresh)",
    )
    assert control_status == "Successful", (
        f"the control refresh ended as {control_status!r}, expected 'Successful'"
    )
    control_members = sorted(_lifecycle_states(ctx, control))
    assert protected[control] not in control_members, (
        f"'Refresh' must replace the scale-in-protected instance {protected[control]}, but it "
        f"is still a member of {control}: {control_members!r}. Without this the subject's "
        f"surviving instance below is not evidence."
    )
    control_dead = _poll(
        lambda: _ec2_state(ctx, protected[control]),
        lambda s: s in ("shutting-down", "terminated"),
        timeout_s=600,
        interval_s=15,
        description=(
            f"the control group's protected instance {protected[control]} was really "
            f"terminated in EC2"
        ),
    )
    assert control_dead in ("shutting-down", "terminated"), (
        f"the control group dropped {protected[control]} but EC2 reports it as "
        f"{control_dead!r}, so the replacement was not real"
    )

    # The subject refresh must also finish -- 'Ignore' means skip, not stall.
    subject_status = _await_refresh(
        ctx, subject, refresh_ids[subject], timeout_s=1800,
        description="the subject refresh (ScaleInProtectedInstances=Ignore)",
    )
    assert subject_status == "Successful", (
        f"the subject refresh ended as {subject_status!r}, expected 'Successful' -- 'Ignore' "
        f"must skip the protected instance, not fail or stall on it"
    )

    # The property under test, read through DescribeAutoScalingInstances rather than the
    # StartInstanceRefresh response that caused it.
    subject_members = sorted(_lifecycle_states(ctx, subject))
    assert protected[subject] in subject_members, (
        f"'Ignore' must spare the scale-in-protected instance {protected[subject]}, but it is "
        f"gone from {subject}: {subject_members!r}"
    )
    assert unprotected[subject] not in subject_members, (
        f"'Ignore' must still replace the UNPROTECTED instance {unprotected[subject]}, but it "
        f"survived the refresh: {subject_members!r}"
    )

    # Terminal read at EC2: the spared instance is the same running machine, not a re-used id.
    spared_state = _ec2_state(ctx, protected[subject])
    assert spared_state == "running", (
        f"the spared instance {protected[subject]} must still be running in EC2, got "
        f"{spared_state!r}"
    )
    replaced_state = _poll(
        lambda: _ec2_state(ctx, unprotected[subject]),
        lambda s: s in ("shutting-down", "terminated"),
        timeout_s=600,
        interval_s=15,
        description=(
            f"the subject's unprotected instance {unprotected[subject]} was really terminated"
        ),
    )
    assert replaced_state in ("shutting-down", "terminated"), (
        f"the subject's unprotected instance {unprotected[subject]} left the group but EC2 "
        f"reports it as {replaced_state!r}"
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



def _lifecycle_states(ctx, name: str) -> dict[str, str]:
    """id -> LifecycleState for every instance the group owns.

    DescribeAutoScalingInstances rather than DescribeAutoScalingGroups: it is a DIFFERENT
    operation from the StartInstanceRefresh under test, and it carries the protection flag too.
    """
    states: dict[str, str] = {}
    paginator = ctx.client("autoscaling").get_paginator("describe_auto_scaling_instances")
    for page in paginator.paginate():
        for inst in page["AutoScalingInstances"]:
            if inst["AutoScalingGroupName"] == name:
                states[inst["InstanceId"]] = inst["LifecycleState"]
    return states


def _protection_flags(ctx, name: str) -> dict[str, bool]:
    flags: dict[str, bool] = {}
    paginator = ctx.client("autoscaling").get_paginator("describe_auto_scaling_instances")
    for page in paginator.paginate():
        for inst in page["AutoScalingInstances"]:
            if inst["AutoScalingGroupName"] == name:
                flags[inst["InstanceId"]] = bool(inst["ProtectedFromScaleIn"])
    return flags


def _refresh(ctx, name: str, refresh_id: str) -> dict:
    asg = ctx.client("autoscaling")
    token = None
    while True:
        # botocore declares no paginator for DescribeInstanceRefreshes (get_paginator raises
        # OperationNotPageableError) although the API takes and returns NextToken, so the token
        # loop is written out by hand. Not a single call: a first-page-only read would silently
        # miss the refresh on a group with many, which is a false "not found".
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


def _await_refresh(ctx, name: str, refresh_id: str, *, timeout_s: float, description: str) -> str:
    """Poll a refresh to Successful, RAISING the moment it lands in a terminal failure.

    A poll whose accept set is only 'Successful' would spin out the full timeout on a Failed
    refresh and report a timeout instead of the failure, so the failure statuses are rejected
    eagerly with the server's own reason attached.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        record = _refresh(ctx, name, refresh_id)
        status = record["Status"]
        if status == "Successful":
            return status
        if status in _FAILED_STATUSES:
            raise AssertionError(
                f"{description} on {name} ended as {status!r}, expected 'Successful': "
                f"{record.get('StatusReason')!r}"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} on {name} did not finish within {timeout_s}s; last "
                f"Status={status!r}, PercentageComplete={record.get('PercentageComplete')!r}"
            )
        time.sleep(2)


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
