"""tag-upsert-filter-and-targeted-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-upsert-filter-and-targeted-delete"
GROUP = 'tags'
SERVICES = ['autoscaling']

_AL2023_SSM_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
# DescribeImages fallback when the execution role has no ssm:GetParameter.
_AMI_NAME_PATTERNS = (
    "al2023-ami-2023.*-kernel-6.1-x86_64",
    "al2023-ami-*-x86_64",
    "amzn2-ami-hvm-*-x86_64-gp2",
)
_CANDIDATE_INSTANCE_TYPES = ("t3.micro", "t2.micro", "t3a.micro")
# The tag the suite stamps on every resource it creates, so a leftover can be found by tag and
# find leftovers. It is also the "unrelated tag" a targeted DeleteTags must not touch.
_MANAGED_TAG_KEY = "sim2real:managed"


def _resolve_ami(ec2, ssm) -> str:
    """Resolve a real, bootable x86_64 Amazon Linux AMI id.

    Auto Scaling data-plane semantics (Pending -> InService -> Terminating, standby,
    refresh, health replacement) are only observable if instances actually launch, so a
    placeholder AMI id would make every state-machine assertion untestable. Prefers the
    public SSM alias (one cheap call), but the execution role may not hold
    ``ssm:GetParameter``, so fall back to EC2 DescribeImages over the Amazon-owned
    Amazon Linux families and take the newest.
    """
    errors: list[str] = []
    try:
        return ssm.get_parameter(Name=_AL2023_SSM_PARAM)["Parameter"]["Value"]
    except Exception as exc:  # noqa: BLE001
        errors.append(f"ssm:{exc}")

    for name_pattern in _AMI_NAME_PATTERNS:
        try:
            images = ec2.describe_images(
                Owners=["amazon"],
                Filters=[
                    {"Name": "name", "Values": [name_pattern]},
                    {"Name": "state", "Values": ["available"]},
                    {"Name": "architecture", "Values": ["x86_64"]},
                    {"Name": "root-device-type", "Values": ["ebs"]},
                    {"Name": "virtualization-type", "Values": ["hvm"]},
                ],
            ).get("Images", [])
        except Exception as exc:  # noqa: BLE001
            errors.append(f"describe_images({name_pattern}):{exc}")
            continue
        if images:
            return max(images, key=lambda i: i.get("CreationDate", ""))["ImageId"]
        errors.append(f"describe_images({name_pattern}):no images")

    raise AssertionError(f"could not resolve a bootable AMI id ({'; '.join(errors)})")


def _network(ec2, *, ctx) -> tuple[str, str, str, str]:
    """(subnet_id, az, instance_type, vpc_id) for a placeable Auto Scaling group."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get(
        "Subnets", []
    )
    if not subnets:
        raise AssertionError(f"no subnets in VPC {vpc_id}")

    offered: set[tuple[str, str]] = set()
    try:
        resp = ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": list(_CANDIDATE_INSTANCE_TYPES)}, {"Name": "location", "Values": ctx.network().availability_zones}],
            MaxResults=1000,
        )
        offered = {
            (o["InstanceType"], o["Location"]) for o in resp.get("InstanceTypeOfferings", [])
        }
    except Exception:  # noqa: BLE001 - best effort; fall back to first subnet
        offered = set()

    for itype in _CANDIDATE_INSTANCE_TYPES:
        for subnet in subnets:
            az = subnet["AvailabilityZone"]
            if not offered or (itype, az) in offered:
                return subnet["SubnetId"], az, itype, vpc_id
    raise AssertionError("no subnet/instance-type combination available")


def _discover_env(ctx):
    """One-shot AMI / subnet / instance-type discovery shared by every group this check builds."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    subnet_id, _az, instance_type, _vpc_id = _network(ec2, ctx=ctx)
    return {
        "ec2": ec2,
        "ami": _resolve_ami(ec2, ssm),
        "subnet": subnet_id,
        "instance_type": instance_type,
    }


def _delete_launch_template(ec2, name) -> None:
    """Delete a launch template, retrying every 2 s while a still-draining group pins it;
    a failure that outlasts the window raises."""
    deadline = time.monotonic() + 30.0
    while True:
        try:
            ec2.delete_launch_template(LaunchTemplateName=name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == (
                "InvalidLaunchTemplateName.NotFoundException"
            ):
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _make_launch_template(ctx, env) -> str:
    """Create an EC2 launch template usable by an Auto Scaling group."""
    name = ctx.unique_name("sim2real-behav-asg-lt-")
    env["ec2"].create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": env["ami"], "InstanceType": env["instance_type"]},
    )
    ctx.on_cleanup(lambda: _delete_launch_template(env["ec2"], name))
    return name


def _make_group(
    ctx,
    as_,
    env,
    *,
    min_size: int = 0,
    max_size: int = 2,
    desired_capacity=None,
    launch_template=None,
    **overrides,
) -> str:
    """Create an Auto Scaling group (and, unless given one, its launch template)."""
    name = ctx.unique_name("sim2real-behav-asg-grp-")
    params: dict = {
        "AutoScalingGroupName": name,
        "MinSize": min_size,
        "MaxSize": max_size,
        "VPCZoneIdentifier": env["subnet"],
        "HealthCheckType": "EC2",
        "HealthCheckGracePeriod": 0,
        "DefaultCooldown": 0,
        "Tags": [{"Key": _MANAGED_TAG_KEY, "Value": "true", "PropagateAtLaunch": True}],
    }
    lt = launch_template or _make_launch_template(ctx, env)
    params["LaunchTemplate"] = {"LaunchTemplateName": lt, "Version": "$Latest"}
    if desired_capacity is not None:
        params["DesiredCapacity"] = desired_capacity
    params.update(overrides)
    as_.create_auto_scaling_group(**params)
    ctx.on_cleanup(
        lambda: as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    )
    return name

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOrUpdateTags upserts by key, DescribeTags filters, and DeleteTags removes only the named key."""
    as_ = ctx.client("autoscaling")
    env = _discover_env(ctx)

    # _make_group stamps the suite's managed tag on the group; that tag is the
    # "unrelated" one the targeted DeleteTags below must leave alone.
    name = _make_group(ctx, as_, env, min_size=0, max_size=1, desired_capacity=0)

    def group_tags():
        return as_.describe_tags(
            Filters=[{"Name": "auto-scaling-group", "Values": [name]}]
        )["Tags"]

    as_.create_or_update_tags(
        Tags=[
            {
                "ResourceId": name,
                "ResourceType": "auto-scaling-group",
                "Key": "behav-key",
                "Value": "v1",
                "PropagateAtLaunch": True,
            }
        ]
    )
    ctx.on_cleanup(
        lambda: as_.delete_tags(
            Tags=[
                {
                    "ResourceId": name,
                    "ResourceType": "auto-scaling-group",
                    "Key": "behav-key",
                }
            ]
        )
    )
    initial_matches = [t for t in group_tags() if t["Key"] == "behav-key"]
    assert len(initial_matches) == 1, f"expected exactly one behav-key tag after create, got {initial_matches}"
    tag = initial_matches[0]
    assert tag["Value"] == "v1", tag
    assert tag["PropagateAtLaunch"] is True, tag
    assert tag["ResourceType"] == "auto-scaling-group", tag
    assert tag["ResourceId"] == name, tag

    # Same key again is an update, not a second tag.
    as_.create_or_update_tags(
        Tags=[
            {
                "ResourceId": name,
                "ResourceType": "auto-scaling-group",
                "Key": "behav-key",
                "Value": "v2",
                "PropagateAtLaunch": False,
            }
        ]
    )
    matches = [t for t in group_tags() if t["Key"] == "behav-key"]
    assert len(matches) == 1, f"upsert must not duplicate a tag key: {matches}"
    assert matches[0]["Value"] == "v2", matches[0]
    assert matches[0]["PropagateAtLaunch"] is False, matches[0]

    by_key = as_.describe_tags(Filters=[{"Name": "key", "Values": ["behav-key"]}])["Tags"]
    assert any(t["ResourceId"] == name for t in by_key), (
        "the key filter must surface the tagged group"
    )

    as_.delete_tags(
        Tags=[
            {
                "ResourceId": name,
                "ResourceType": "auto-scaling-group",
                "Key": "behav-key",
            }
        ]
    )
    remaining = {t["Key"] for t in group_tags()}
    assert "behav-key" not in remaining, remaining
    assert _MANAGED_TAG_KEY in remaining, (
        "a targeted DeleteTags must not remove unrelated tags"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
