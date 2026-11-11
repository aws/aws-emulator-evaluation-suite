"""set-desired-capacity-above-max-size-rejected-and-no-instance-is-launched."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-desired-capacity-above-max-size-rejected-and-no-instance-is-launched"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """SetDesiredCapacity above MaxSize is refused and leaves DesiredCapacity and instances unchanged,
    while the same call within MaxSize launches a second instance (so a blanket refusal fails).
    """
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    _vpc, subnets = _usable_subnets(ctx, "t3.micro", want=2)
    lt_name = _launch_template(ctx, ami)
    name = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=2, desired=1)

    ids_before = set(_poll(
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=600,
        description="setup: the group reached 1 InService instance",
    ))
    assert _group(ctx, name)["MaxSize"] == 2, (
        f"setup: MaxSize must be 2 for the rejection to be about MaxSize, got "
        f"{_group(ctx, name)['MaxSize']!r}"
    )

    # Break exactly one thing: ask for 5 in a group whose MaxSize is 2.
    code, message = _error(lambda: asg.set_desired_capacity(
        AutoScalingGroupName=name, DesiredCapacity=5, HonorCooldown=False
    ))
    assert code == "ValidationError", (
        f"a desired capacity above MaxSize was accepted or refused with the wrong code: {code!r}"
    )
    assert message == (
        "New SetDesiredCapacity value 5 is above max value 2 for the AutoScalingGroup."
    ), f"unexpected ValidationError message: {message!r}"

    desired_after_reject = _group(ctx, name)["DesiredCapacity"]
    assert desired_after_reject == 1, (
        f"the rejected call changed DesiredCapacity: {desired_after_reject!r}"
    )

    # Effect that must be ABSENT: no launch, no termination. Held for 120s rather than sampled
    # once, because a launch the rejection wrongly started would take that long to appear.
    ids_after_reject = set(_holds_for(
        lambda: (set(_ids_in_state(ctx, name, "InService", "Pending", "Pending:Wait")),
                 _group(ctx, name)["DesiredCapacity"]),
        lambda pair: pair[0] == ids_before and pair[1] == 1,
        seconds=120,
        description="the rejected SetDesiredCapacity must leave the instance set and "
                    "DesiredCapacity untouched",
    )[0])
    assert ids_after_reject == ids_before, (
        f"the rejected call launched or terminated instances: "
        f"{sorted(ids_after_reject ^ ids_before)!r}"
    )

    # Positive control, same group, same call, one unit lower: this one must really launch.
    asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=2, HonorCooldown=False)
    ids_after_legal = set(_poll(
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == 2,
        timeout_s=600,
        description="the legal capacity change launched a second InService instance",
    ))
    assert len(ids_after_legal) == 2, (
        f"the legal capacity change did not launch an instance: {sorted(ids_after_legal)!r}"
    )
    assert ids_before < ids_after_legal, (
        f"the legal change replaced the original instance instead of adding one: "
        f"before {sorted(ids_before)!r}, after {sorted(ids_after_legal)!r}"
    )
    new_id = (ids_after_legal - ids_before).pop()
    assert _ec2_state(ctx, new_id) == "running", (
        f"the instance the legal capacity change launched is not running: "
        f"{_ec2_state(ctx, new_id)!r}"
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


def _holds_for(fn, pred, *, seconds, interval_s=10, description="condition"):
    """Assert pred() holds continuously for `seconds` -- proves an effect stayed ABSENT."""
    deadline = time.monotonic() + seconds
    while True:
        val = fn()
        if not pred(val):
            raise AssertionError(f"{description} stopped holding; observed {val!r}")
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    """The exact AWS error code and message fn() raises.

    Raises when the call succeeds, so accepting rejected input is never reported as a code mismatch.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("the call was expected to be rejected but it succeeded")


def _al2023_ami(ctx) -> str:
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    value = ctx.client("ssm").get_parameter(Name=param)["Parameter"]["Value"]
    assert value.startswith("ami-"), f"{param} did not resolve to an AMI: {value!r}"
    return value


def _usable_subnets(ctx, instance_type: str, want: int = 1):
    """Default-VPC subnets in available AZs that offer instance_type.

    Type offerings do not report zone state and zone state says nothing about instance types.
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
    """A launch template tagging both the instance and its volume at launch, so ASG-created
    instances and volumes stay attributable even if teardown is interrupted."""
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
        # An ASG left with capacity RELAUNCHES the instances you just deleted, so cleanup has to
        # drain the group to zero FIRST, then ForceDelete, then WAIT for the group to actually
        # disappear -- only then may the launch-template teardown registered earlier (LIFO: it
        # runs after this one) find the template unreferenced.
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
