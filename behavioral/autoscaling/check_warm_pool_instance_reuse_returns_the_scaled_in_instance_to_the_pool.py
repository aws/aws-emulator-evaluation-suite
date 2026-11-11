"""warm-pool-instance-reuse-returns-the-scaled-in-instance-to-the-pool."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "warm-pool-instance-reuse-returns-the-scaled-in-instance-to-the-pool"
GROUP = "warm-pool"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With ReuseOnScaleIn, the same InService instance returns to the warm pool stopped on scale-in,
    while a twin group without the policy terminates its instance.

    Reference: https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-warm-pools.html
    """
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    _vpc, _azs, subnets = _network(ctx, "t3.micro", want=1)
    lt_name = _launch_template(ctx, ami)
    control = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=2, desired=1)
    subject = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=2, desired=1)

    # Break exactly one thing: only the subject may reuse.
    asg.put_warm_pool(AutoScalingGroupName=control, MinSize=1, PoolState="Stopped")
    ctx.on_cleanup(lambda: _unless_gone(lambda: asg.delete_warm_pool(
        AutoScalingGroupName=control, ForceDelete=True)))
    asg.put_warm_pool(
        AutoScalingGroupName=subject,
        MinSize=1,
        PoolState="Stopped",
        InstanceReusePolicy={"ReuseOnScaleIn": True},
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: asg.delete_warm_pool(
        AutoScalingGroupName=subject, ForceDelete=True)))

    control_policy = _warm_pool(ctx, control).get("InstanceReusePolicy")
    assert not control_policy, (
        f"the control group must have no instance reuse policy, got {control_policy!r}"
    )
    subject_policy = _warm_pool(ctx, subject).get("InstanceReusePolicy")
    assert subject_policy == {"ReuseOnScaleIn": True}, (
        f"the subject group did not record the reuse policy: expected "
        f"{{'ReuseOnScaleIn': True}}, got {subject_policy!r}"
    )

    control_served = _poll(
        lambda: _ids_in_state(ctx, control, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=_budget_s(ctx, 1500),
        interval_s=2,
        ctx=ctx,
        description="setup: the control group reached 1 InService instance",
    )[0]
    subject_served = _poll(
        lambda: _ids_in_state(ctx, subject, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=_budget_s(ctx, 1500),
        interval_s=2,
        ctx=ctx,
        description="setup: the subject group reached 1 InService instance",
    )[0]
    assert control_served != subject_served, (
        f"the two groups must hold different instances, both report {control_served!r}"
    )
    # A settled warm pool on both sides, so the scale-in below is not racing provisioning.
    for name in (control, subject):
        warmed = _poll(
            lambda name=name: _ids_with_prefix(ctx, name, "Warmed:"),
            lambda ids: len(ids) == 1,
            timeout_s=_budget_s(ctx, 1500),
            interval_s=2,
            ctx=ctx,
            description=f"setup: {name} settled with 1 warm-pool instance",
        )
        assert len(warmed) == 1, (
            f"setup: {name} must hold exactly 1 warm-pool instance before the scale-in, "
            f"got {warmed!r}"
        )

    # One fan-out, same instant, so no propagation delta exists between the two groups.
    for name in (control, subject):
        asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=0)

    # The control's termination proves the scale-in happened, so the subject's survival is evidence.
    control_dead = _poll(
        lambda: _ec2_state(ctx, control_served),
        lambda s: s in ("shutting-down", "terminated"),
        timeout_s=_budget_s(ctx, 1200),
        interval_s=2,
        ctx=ctx,
        description=(
            f"the control group (no reuse policy) really terminated its InService instance "
            f"{control_served} in EC2"
        ),
    )
    assert control_dead in ("shutting-down", "terminated"), (
        f"the control group did not terminate {control_served} on scale-in (EC2 reports "
        f"{control_dead!r}), so the subject's surviving instance below is not evidence"
    )
    # ASG bookkeeping lags EC2: LifecycleState can still read 'Terminating' after EC2 shows
    # shutting-down/terminated, so poll for convergence.
    control_states = _poll(
        lambda: _lifecycle_states(ctx, control),
        lambda states: control_served not in states,
        timeout_s=_budget_s(ctx, 600),
        interval_s=2,
        ctx=ctx,
        description=(
            f"the control group's scaled-in instance {control_served} left the group "
            f"entirely, per DescribeAutoScalingInstances"
        ),
    )
    assert control_served not in control_states, (
        f"the control group's scaled-in instance {control_served} must leave the group "
        f"entirely, but it is still reported as {control_states.get(control_served)!r}"
    )

    # The subject's instance is not destroyed at the moment destruction is proven possible.
    subject_state_now = _ec2_state(ctx, subject_served)
    assert subject_state_now not in ("shutting-down", "terminated"), (
        f"the reuse policy did not spare {subject_served}: EC2 reports {subject_state_now!r} "
        f"at the same instant the control group's instance was confirmed destroyed"
    )

    # Terminal read: the SAME instance is back in the pool, and EC2 agrees it is stopped.
    reused_state = _poll(
        lambda: _lifecycle_states(ctx, subject).get(subject_served, "absent"),
        lambda s: s.startswith("Warmed:"),
        timeout_s=_budget_s(ctx, 1200),
        interval_s=2,
        ctx=ctx,
        description=(
            f"the scaled-in instance {subject_served} returned to the subject's warm pool "
            f"under a Warmed:* lifecycle state"
        ),
    )
    assert reused_state.startswith("Warmed:"), (
        f"the reuse policy did not return {subject_served} to the warm pool: its lifecycle "
        f"state is {reused_state!r}, expected a Warmed:* state"
    )
    stopped = _poll(
        lambda: _ec2_state(ctx, subject_served),
        lambda s: s == "stopped",
        timeout_s=_budget_s(ctx, 900),
        interval_s=2,
        ctx=ctx,
        description=(
            f"the reused instance {subject_served} reached EC2 state 'stopped', matching the "
            f"warm pool's PoolState=Stopped"
        ),
    )
    assert stopped == "stopped", (
        f"the reused instance {subject_served} must be stopped, not destroyed and not left "
        f"running: EC2 reports {stopped!r}"
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
            msg = err.get("Message", "").lower()
            if "NotFound" in code or code == "NoSuchEntity" or (
                code == "ValidationError" and ("not found" in msg or "no warm pool found" in msg)
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


def _poll(fn, pred, *, timeout_s, interval_s=2, description="condition", ctx=None):
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



def _warm_pool(ctx, name: str) -> dict:
    """DescribeWarmPool's configuration record for the group."""
    resp = ctx.client("autoscaling").describe_warm_pool(AutoScalingGroupName=name)
    config = resp.get("WarmPoolConfiguration")
    assert config, f"no warm pool configuration reported for group {name!r}: {resp!r}"
    return config


def _lifecycle_states(ctx, name: str) -> dict[str, str]:
    """id -> LifecycleState for every instance the group owns, warm pool included.

    DescribeAutoScalingInstances carries the Warmed:* states; DescribeAutoScalingGroups does not.
    """
    states: dict[str, str] = {}
    paginator = ctx.client("autoscaling").get_paginator("describe_auto_scaling_instances")
    for page in paginator.paginate():
        for inst in page["AutoScalingInstances"]:
            if inst["AutoScalingGroupName"] == name:
                states[inst["InstanceId"]] = inst["LifecycleState"]
    return states


def _ids_with_prefix(ctx, name: str, prefix: str) -> list[str]:
    return sorted(
        instance_id
        for instance_id, state in _lifecycle_states(ctx, name).items()
        if state.startswith(prefix)
    )


# Async deletes (instances, ENI-owning services) leave ENIs behind briefly, so network deletes wait
# (bounded) for ENIs to go and retry DependencyViolation, then fail naming the ENIs still attached.
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
