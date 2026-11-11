"""instance-refresh-replaces-every-instance-with-the-new-launch-template-version."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-refresh-replaces-every-instance-with-the-new-launch-template-version"
GROUP = "instance-refresh"
SERVICES = ["autoscaling"]

_V1_TYPE = "t3.micro"
_V2_TYPE = "t3.small"


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
    """A refresh after a launch-template bump replaces every instance: before and after id sets are
    disjoint, the originals are gone from EC2, and replacements run version 2's instance type.
    """
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    ami = _al2023_ami(ctx)
    _vpc, subnets = _usable_subnets(ctx, _V1_TYPE, want=2)
    lt_name = _launch_template(ctx, ami, instance_type=_V1_TYPE)
    # Pinned to version 1, so bumping the pointer to $Latest later is a real configuration change.
    name = _create_asg(ctx, lt_name, subnets, min_size=2, max_size=2, desired=2, lt_version="1")

    old_ids = _poll(
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == 2,
        timeout_s=1200,
        interval_s=15,
        description="setup: the group reached 2 InService instances on launch template version 1",
    )
    old_versions = {v for v in _instance_lt_versions(ctx, name).values()}
    assert old_versions == {"1"}, (
        f"setup: the original instances must all reference version 1: {old_versions!r}"
    )
    for iid in old_ids:
        assert _instance_type(ctx, iid) == _V1_TYPE, (
            f"setup: {iid} runs {_instance_type(ctx, iid)!r}, not the version-1 type {_V1_TYPE!r}"
        )

    version_2 = ec2.create_launch_template_version(
        LaunchTemplateName=lt_name,
        SourceVersion="1",
        LaunchTemplateData={"InstanceType": _V2_TYPE},
    )["LaunchTemplateVersion"]["VersionNumber"]
    assert version_2 == 2, f"the new launch template version is not 2: {version_2!r}"
    asg.update_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
    )

    refresh_id = asg.start_instance_refresh(
        AutoScalingGroupName=name,
        Preferences={"MinHealthyPercentage": 0, "InstanceWarmup": 0},
    )["InstanceRefreshId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: asg.cancel_instance_refresh(
        AutoScalingGroupName=name
    ), "ActiveInstanceRefreshNotFound"))

    refresh = _poll(
        lambda: _refresh(ctx, name, refresh_id),
        lambda r: r["Status"] in ("Successful", "Failed", "Cancelled", "RollbackSuccessful",
                                 "RollbackFailed"),
        timeout_s=1800,
        interval_s=20,
        description=f"instance refresh {refresh_id} reached a terminal status",
    )
    assert refresh["Status"] == "Successful", (
        f"the refresh did not complete successfully: {refresh['Status']!r}, "
        f"{refresh.get('StatusReason')!r}"
    )
    assert refresh["PercentageComplete"] == 100, (
        f"the refresh reported Successful at {refresh['PercentageComplete']!r}% complete"
    )

    new_ids = _poll(
        lambda: _ids_in_state(ctx, name, "InService"),
        lambda ids: len(ids) == 2 and not set(ids) & set(old_ids),
        timeout_s=1200,
        interval_s=15,
        description="the refreshed group holds 2 InService instances, none of them original",
    )
    assert set(new_ids).isdisjoint(old_ids), (
        f"the refresh did not replace the instances: {sorted(set(new_ids) & set(old_ids))!r} survived"
    )
    new_versions = set(_instance_lt_versions(ctx, name).values())
    assert "1" not in new_versions, (
        f"a refreshed instance still references launch template version 1: {new_versions!r}"
    )
    for iid in new_ids:
        actual = _instance_type(ctx, iid)
        assert actual == _V2_TYPE, (
            f"the refreshed instance {iid} runs {actual!r}, not the version-2 type {_V2_TYPE!r} -- "
            f"the refresh relaunched on the old launch template version"
        )
    group = _group(ctx, name)
    assert len(new_ids) == 2 and group["DesiredCapacity"] == 2, (
        f"the refresh changed the group size: {len(new_ids)!r} instances, DesiredCapacity "
        f"{group['DesiredCapacity']!r}"
    )
    old_states = {iid: _ec2_state(ctx, iid) for iid in old_ids}
    assert all(s in ("shutting-down", "terminated") for s in old_states.values()), (
        f"the original instances are still running after the refresh: {old_states!r}"
    )


_MANAGED_TAGS = {"sim2real": "as-depth", "sim2real:managed": "true"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _unless_gone(fn, *not_found):
    """Run one cleanup call; only a not-found answer means the resource is already gone."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] in not_found or (
                err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
            return
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
    server-minted instance and volume ids an ASG creates stay attributable and reapable.

    Deleting the template by name removes every version, so the version created later needs no
    cleanup of its own."""
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


def _instance_lt_versions(ctx, name: str) -> dict[str, str]:
    """{instance-id: the launch template Version the group records for it}."""
    return {
        i["InstanceId"]: i["LaunchTemplate"]["Version"]
        for i in _group(ctx, name)["Instances"] if "LaunchTemplate" in i
    }


def _refresh(ctx, name: str, refresh_id: str) -> dict:
    """The named refresh, paginated on NextToken.

    botocore ships no paginator for DescribeInstanceRefreshes, so the token loop is hand-rolled;
    earlier refreshes on the same group can push later ones off page one.
    """
    asg = ctx.client("autoscaling")
    token = None
    while True:
        kwargs = {"AutoScalingGroupName": name}
        if token:
            kwargs["NextToken"] = token
        resp = asg.describe_instance_refreshes(**kwargs)
        for ref in resp.get("InstanceRefreshes", []):
            if ref["InstanceRefreshId"] == refresh_id:
                return ref
        token = resp.get("NextToken")
        if not token:
            raise AssertionError(
                f"instance refresh {refresh_id!r} not found on group {name!r}"
            )


def _instance_type(ctx, instance_id: str) -> str:
    return _instance(ctx, instance_id)["InstanceType"]


def _ec2_state(ctx, instance_id: str) -> str:
    return _instance(ctx, instance_id)["State"]["Name"]


def _instance(ctx, instance_id: str) -> dict:
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=[instance_id]):
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst
    raise AssertionError(f"instance {instance_id!r} not found in DescribeInstances")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
