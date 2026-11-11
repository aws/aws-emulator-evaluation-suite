"""complete-lifecycle-action-reused-on-a-consumed-action-rejected-and-the-instance-stays-waiting."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "complete-lifecycle-action-reused-on-a-consumed-action-rejected-and-the-instance-stays-waiting"
)
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
    """Completing an already-consumed lifecycle action is refused, and the instance stays held at
    Pending:Wait by a second hook, whose own CompleteLifecycleAction then admits it to InService.
    """
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    _vpc, subnets = _usable_subnets(ctx, "t3.micro", want=2)
    lt_name = _launch_template(ctx, ami)
    name = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=1, desired=0)

    hook_a = ctx.unique_name("sim2real-behav-as-hooka-")
    hook_b = ctx.unique_name("sim2real-behav-as-hookb-")
    for hook in (hook_a, hook_b):
        asg.put_lifecycle_hook(
            LifecycleHookName=hook,
            AutoScalingGroupName=name,
            LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
            HeartbeatTimeout=3600,
            DefaultResult="CONTINUE",
        )
        ctx.on_cleanup(lambda h=hook: _unless_gone(lambda: asg.delete_lifecycle_hook(
            LifecycleHookName=h, AutoScalingGroupName=name
        )))
    installed = {h["LifecycleHookName"] for h in asg.describe_lifecycle_hooks(
        AutoScalingGroupName=name
    )["LifecycleHooks"]}
    assert {hook_a, hook_b} <= installed, (
        f"both launching hooks must be on the group before the launch: {sorted(installed)!r}"
    )

    asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1, HonorCooldown=False)
    instance_id_before = _poll(
        lambda: _ids_in_state(ctx, name, "Pending:Wait"),
        lambda ids: len(ids) == 1,
        timeout_s=600,
        description="the two launching hooks held an instance at Pending:Wait",
    )[0]

    # Addressed by InstanceId: a token is only delivered to a hook's notification target, and
    # these hooks have none. One of two hooks is now satisfied, so the instance stays held.
    asg.complete_lifecycle_action(
        LifecycleHookName=hook_a,
        AutoScalingGroupName=name,
        LifecycleActionResult="CONTINUE",
        InstanceId=instance_id_before,
    )
    assert _state_of(ctx, name, instance_id_before) == "Pending:Wait", (
        f"completing one of two outstanding hooks already advanced the instance: "
        f"{_state_of(ctx, name, instance_id_before)!r}"
    )

    # --- Break exactly one thing: repeat that same call on the action it already consumed.
    code, message = _client_error(lambda: asg.complete_lifecycle_action(
        LifecycleHookName=hook_a,
        AutoScalingGroupName=name,
        LifecycleActionResult="CONTINUE",
        InstanceId=instance_id_before,
    ))
    assert code == "ValidationError", (
        f"a lifecycle action that had already been consumed was completed again, or refused with "
        f"the wrong code: {code!r}"
    )
    assert message == (
        f"No active Lifecycle Action found with instance ID {instance_id_before} and HookName {hook_a}"
    ), f"expected the exact refusal message, got {message!r}"

    # Effect that must be ABSENT: the refused call may not have released the instance, which is
    # still held by hook B.
    states_after_reuse = set(_holds_for(
        lambda: {i["LifecycleState"] for i in _group(ctx, name)["Instances"]
                 if i["InstanceId"] == instance_id_before},
        lambda states: states == {"Pending:Wait"},
        seconds=120,
        interval_s=10,
        description=f"after the refusal {instance_id_before} must still be held at Pending:Wait "
                    f"by hook B",
    ))
    assert states_after_reuse == {"Pending:Wait"}, (
        f"the reused lifecycle action advanced the instance: {sorted(states_after_reuse)!r}"
    )

    # --- Positive control: hook B's own action admits the SAME instance.
    asg.complete_lifecycle_action(
        LifecycleHookName=hook_b,
        AutoScalingGroupName=name,
        LifecycleActionResult="CONTINUE",
        InstanceId=instance_id_before,
    )
    final_state = _poll(
        lambda: _state_of(ctx, name, instance_id_before),
        lambda s: s == "InService",
        timeout_s=600,
        description=f"hook B's own action admitted {instance_id_before} to InService",
    )
    assert final_state == "InService", (
        f"the remaining hook's own action did not admit the instance: {final_state!r}"
    )
    instance_id_after = _ids_in_state(ctx, name, "InService")[0]
    assert instance_id_before == instance_id_after, (
        f"the instance was replaced rather than admitted: {instance_id_before!r} -> "
        f"{instance_id_after!r}"
    )
    assert _ec2_state(ctx, instance_id_after) == "running", (
        f"the admitted instance is InService but EC2 says {_ec2_state(ctx, instance_id_after)!r}"
    )


_MANAGED_TAGS = {"sim2real": "as-depth", "sim2real:managed": "true"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _unless_gone(fn, *tolerated):
    """Run a teardown step; only Auto Scaling's "not found" ValidationError (or a tolerated code) passes."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        msg = err.get("Message", "")
        if err["Code"] in tolerated:
            return
        if not (err["Code"] == "ValidationError" and ("not found" in msg or "No Lifecycle Hook found" in msg)):
            raise


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


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, because accepting a call AWS refuses is itself the failure."""

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
        # An ASG left with capacity RELAUNCHES the instances you just deleted -- and a launching
        # lifecycle hook makes that worse, because each relaunch parks a fresh instance at
        # Pending:Wait. Drain to zero FIRST, then ForceDelete, then WAIT for the group to
        # disappear; only then may the launch-template teardown registered earlier succeed.
        # A busy group refuses the drain; the ForceDelete below still removes it.
        _unless_gone(lambda: asg.update_auto_scaling_group(
            AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0),
            "ScalingActivityInProgress", "ResourceContention")
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


def _state_of(ctx, name: str, instance_id: str) -> str:
    for inst in _group(ctx, name)["Instances"]:
        if inst["InstanceId"] == instance_id:
            return inst["LifecycleState"]
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
