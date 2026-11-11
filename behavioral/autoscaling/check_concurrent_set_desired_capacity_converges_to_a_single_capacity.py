"""concurrent-set-desired-capacity-converges-to-a-single-capacity."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-set-desired-capacity-converges-to-a-single-capacity"
GROUP = "concurrency"
SERVICES = ["autoscaling"]

_REQUESTED = (0, 1, 2, 3, 2)
_MAX_SIZE = 3


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
    """Five racing SetDesiredCapacity calls settle on one of the requested values, the group's running
    instance count equals it once quiet, and MaxSize is never exceeded on the way."""
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    _vpc, subnets = _usable_subnets(ctx, "t3.micro", want=2)
    lt_name = _launch_template(ctx, ami)
    name = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=_MAX_SIZE, desired=1)

    _poll(
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=900,
        description="setup: the group reached 1 InService instance",
    )

    def _set(value: int):
        try:
            asg.set_desired_capacity(
                AutoScalingGroupName=name, DesiredCapacity=value, HonorCooldown=False
            )
        except ClientError as exc:
            return exc.response["Error"]["Code"]
        return None

    with ThreadPoolExecutor(max_workers=len(_REQUESTED)) as pool:
        outcomes = list(pool.map(_set, _REQUESTED))
    errors = [c for c in outcomes if c is not None]
    # ScalingActivityInProgress is the ONE refusal AWS is allowed to give a capacity change that
    # races another: anything else means a concurrent capacity change failed for a reason the
    # service does not document, which is a finding rather than contention.
    assert set(errors) <= {"ScalingActivityInProgress"}, (
        f"a concurrent capacity change failed unexpectedly: {errors!r} "
        f"(all five outcomes were {outcomes!r})"
    )

    observed_live: list[int] = []

    def _probe():
        group = _group(ctx, name)
        states = [i["LifecycleState"] for i in group["Instances"]]
        # MaxSize bounds the instances that are in or entering service; an instance already
        # Terminating on the way down is not capacity the group is holding.
        observed_live.append(len([s for s in states if not s.startswith("Terminating")]))
        return group["DesiredCapacity"], states

    final_desired, final_states = _poll(
        _probe,
        lambda pair: all(s == "InService" for s in pair[1])
        and len(pair[1]) == pair[0],
        timeout_s=1200,
        interval_s=15,
        description="the group went quiet with every instance InService and the count equal to "
                    "DesiredCapacity",
    )

    assert final_desired in set(_REQUESTED), (
        f"the settled desired capacity is not one of the requested values {sorted(set(_REQUESTED))!r}: "
        f"{final_desired!r}"
    )
    in_service = _ids_in_state(ctx, name, "InService")
    assert len(in_service) == final_desired, (
        f"the group did not converge to its desired capacity: {len(in_service)!r} InService "
        f"({in_service!r}) != DesiredCapacity {final_desired!r}"
    )
    assert all(s == "InService" for s in final_states), (
        f"the group settled with instances in a transitional state: {final_states!r}"
    )
    max_observed = max(observed_live)
    assert max_observed <= _MAX_SIZE, (
        f"the group exceeded MaxSize during convergence: observed {max_observed!r} instances in or "
        f"entering service, MaxSize is {_MAX_SIZE!r} (samples {observed_live!r})"
    )
    for iid in in_service:
        state = _ec2_state(ctx, iid)
        assert state == "running", (
            f"the group reports {iid} InService but EC2 says {state!r}"
        )


_MANAGED_TAGS = {"sim2real": "as-depth", "sim2real:managed": "true"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown
        pass


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
