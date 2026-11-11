"""set-instance-health-inside-the-grace-period-rejected-and-the-instance-is-not-replaced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-instance-health-inside-the-grace-period-rejected-and-the-instance-is-not-replaced"
GROUP = "instance-lifecycle"
SERVICES = ["autoscaling"]

_GRACE_S = 900


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
    """SetInstanceHealth with ShouldRespectGracePeriod=True inside the grace period is rejected and
    the instance keeps running; the same call with the flag off is accepted and replaces it.
    """
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    _vpc, subnets = _usable_subnets(ctx, "t3.micro", want=2)
    lt_name = _launch_template(ctx, ami)
    name = _create_asg(
        ctx, lt_name, subnets, min_size=1, max_size=1, desired=1,
        HealthCheckType="EC2", HealthCheckGracePeriod=_GRACE_S,
    )
    # An identical twin whose instance is marked Unhealthy with the flag off: its replacement is
    # the ordered contrast for the subject's absent one.
    twin = _create_asg(
        ctx, lt_name, subnets, min_size=1, max_size=1, desired=1,
        HealthCheckType="EC2", HealthCheckGracePeriod=_GRACE_S,
    )

    original_id = _poll(
        ctx,
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=900,
        description="setup: the group reached 1 InService instance",
    )[0]
    in_service_at = time.monotonic()
    grace = _group(ctx, name)["HealthCheckGracePeriod"]
    assert grace == _GRACE_S, (
        f"setup: the grace period must be {_GRACE_S}s for this call to be inside it, got {grace!r}"
    )

    # AWS rejects this outright (ValidationError) rather than accepting and deferring it.
    code, message = _error_code_and_message(lambda: asg.set_instance_health(
        InstanceId=original_id, HealthStatus="Unhealthy", ShouldRespectGracePeriod=True
    ))
    assert code == "ValidationError", (
        f"marking an instance Unhealthy inside its grace period while respecting that grace period "
        f"was accepted, or refused with the wrong code: {code!r}"
    )
    # message varies: AWS embeds the instance's server-measured age in seconds, which no value
    # the check controls can predict; every other character is asserted exactly.
    age = message.split("(", 1)[1].split(" seconds)", 1)[0] if "(" in message else ""
    assert age.isdigit() and int(age) < _GRACE_S, (
        f"the refusal must report an instance age inside the grace period: {message!r}"
    )
    assert message == (
        f"The age of the instance ({age} seconds) is less than the configured grace period of "
        f"{_GRACE_S} seconds"
    ), (
        f"the ValidationError must name the grace period as the reason for the refusal, not some "
        f"other validation failure: {message!r}"
    )

    # Effect that must be ABSENT: the refused call may not have started a replacement. Proven
    # by contrast: once the twin's accepted call has replaced its instance, the subject is read.
    twin_original = _poll(
        ctx,
        lambda: _ids_in_state(ctx, twin, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=900,
        description="setup: the twin group reached 1 InService instance",
    )[0]
    asg.set_instance_health(
        InstanceId=twin_original, HealthStatus="Unhealthy", ShouldRespectGracePeriod=False
    )
    _poll(
        ctx,
        lambda: _ids_in_state(ctx, twin, "InService"),
        lambda ids: len(ids) == 1 and ids[0] != twin_original,
        timeout_s=1200,
        description=f"the twin's accepted call replaced {twin_original} with a new InService "
                    f"instance",
    )
    ids_during_grace = set(_all_ids(ctx, name))
    states_during_grace = set(_lifecycle_states(ctx, name))
    assert ids_during_grace == {original_id}, (
        f"the refused call replaced the instance anyway: {sorted(ids_during_grace)!r}"
    )
    assert states_during_grace == {"InService"}, (
        f"the instance left InService after the refused call: {sorted(states_during_grace)!r}"
    )
    elapsed = time.monotonic() - in_service_at
    assert elapsed < _GRACE_S, (
        f"the no-replacement read came {elapsed:.0f}s past InService, outside the {_GRACE_S}s "
        f"grace period it was supposed to be inside -- the absence would prove nothing"
    )
    assert _ec2_state(ctx, original_id) == "running", (
        f"the instance is not running after the refused call: {_ec2_state(ctx, original_id)!r}"
    )

    # Positive control: the same call with the flag off is accepted and replaces the instance.
    asg.set_instance_health(
        InstanceId=original_id, HealthStatus="Unhealthy", ShouldRespectGracePeriod=False
    )
    replacement_id = _poll(
        ctx,
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == 1 and ids[0] != original_id,
        timeout_s=1200,
        description=f"ignoring the grace period replaced {original_id} with a new InService "
                    f"instance",
    )[0]
    assert replacement_id != original_id, (
        f"ignoring the grace period did not trigger a replacement: still {replacement_id!r}"
    )
    original_state = _poll(
        ctx,
        lambda: _ec2_state(ctx, original_id),
        lambda s: s in ("shutting-down", "terminated"),
        timeout_s=600,
        description=f"the original instance {original_id} was really terminated",
    )
    assert original_state in ("shutting-down", "terminated"), (
        f"the original instance was not terminated on the second leg: {original_state!r}"
    )
    assert _ec2_state(ctx, replacement_id) == "running", (
        f"the replacement instance is not running: {_ec2_state(ctx, replacement_id)!r}"
    )

    causes = [
        a["Cause"] for a in _activities(ctx, name)
        if original_id in f"{a.get('Description', '')} {a.get('Cause', '')}"
        and "health" in a.get("Cause", "").lower()
    ]
    assert causes, (
        f"no health-triggered scaling activity was recorded for {original_id}; the causes on the "
        f"group were {[a.get('Cause') for a in _activities(ctx, name)]!r}"
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


def _poll(ctx, fn, pred, *, timeout_s, interval_s=2, description="condition"):
    """Poll fn() until pred() holds; raise with the last observed value on timeout."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


def _error_code(fn) -> str:
    """The exact AWS error code fn() raises.

    Raises when the call succeeds, so accepting rejected input is never reported as a code mismatch.
    """
    return _error_code_and_message(fn)[0]


def _error_code_and_message(fn) -> tuple[str, str]:
    """The exact AWS error code and message fn() raises; raises on unexpected success (see
    _error_code)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
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
    instances and volumes stay attributable."""
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


def _all_ids(ctx, name: str) -> list[str]:
    return sorted(i["InstanceId"] for i in _group(ctx, name)["Instances"])


def _lifecycle_states(ctx, name: str) -> list[str]:
    return sorted(i["LifecycleState"] for i in _group(ctx, name)["Instances"])


def _ids_in_state(ctx, name: str, *states: str) -> list[str]:
    return sorted(
        i["InstanceId"] for i in _group(ctx, name)["Instances"]
        if i["LifecycleState"] in states
    )


def _activities(ctx, name: str) -> list[dict]:
    acts = []
    for page in ctx.client("autoscaling").get_paginator(
        "describe_scaling_activities"
    ).paginate(AutoScalingGroupName=name):
        acts += page["Activities"]
    return acts


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
