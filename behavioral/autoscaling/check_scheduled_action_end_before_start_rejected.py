"""scheduled-action-end-before-start-rejected."""
from __future__ import annotations

import datetime as dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduled-action-end-before-start-rejected"
GROUP = 'overly-permissive'
SERVICES = ['autoscaling']

def _error(fn):
    """Call fn(); return its (error code, error message). Raises on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


_AL2023_SSM_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
# DescribeImages fallback when the execution role has no ssm:GetParameter.
_AMI_NAME_PATTERNS = (
    "al2023-ami-2023.*-kernel-6.1-x86_64",
    "al2023-ami-*-x86_64",
    "amzn2-ami-hvm-*-x86_64-gp2",
)
_CANDIDATE_INSTANCE_TYPES = ("t3.micro", "t2.micro", "t3a.micro")
# Tag stamped on every resource this check creates so leftovers can be found.
_MANAGED_TAG_KEY = "sim2real:managed"


def _resolve_ami(ec2, ssm) -> str:
    """Resolve a real bootable x86_64 Amazon Linux AMI id so instances actually launch.
    Prefers the public SSM alias; falls back to the newest DescribeImages match without
    ``ssm:GetParameter``."""
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
        TagSpecifications=[
            {
                "ResourceType": "launch-template",
                "Tags": [{"Key": _MANAGED_TAG_KEY, "Value": "true"}],
            }
        ],
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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A scheduled action whose EndTime precedes its StartTime is rejected; a well-formed action is
    accepted and visible first, so the rejection is about the bad window, not every call."""
    as_ = ctx.client("autoscaling")
    env = _discover_env(ctx)

    name = _make_group(ctx, as_, env, min_size=0, max_size=2, desired_capacity=0)
    start = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)

    good_name = ctx.unique_name("sim2real-behav-asg-good-")
    as_.put_scheduled_update_group_action(
        AutoScalingGroupName=name,
        ScheduledActionName=good_name,
        StartTime=start,
        EndTime=start + dt.timedelta(days=1),
        DesiredCapacity=1,
    )
    actions = as_.describe_scheduled_actions(AutoScalingGroupName=name)[
        "ScheduledUpdateGroupActions"
    ]
    assert any(a["ScheduledActionName"] == good_name for a in actions), (
        "positive control: a well-formed scheduled action must be created and visible"
    )

    bad_name = ctx.unique_name("sim2real-behav-asg-bad-")
    code, message = _error(
        lambda: as_.put_scheduled_update_group_action(
            AutoScalingGroupName=name,
            ScheduledActionName=bad_name,
            StartTime=start,
            EndTime=start - dt.timedelta(days=1),
            DesiredCapacity=1,
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    assert message == "Given end time must be after start time", (
        f"unexpected ValidationError message: {message!r}"
    )
    actions_after = as_.describe_scheduled_actions(AutoScalingGroupName=name)[
        "ScheduledUpdateGroupActions"
    ]
    names_after = {a["ScheduledActionName"] for a in actions_after}
    assert bad_name not in names_after, "no action may be created from a rejected put"
    assert good_name in names_after, (
        "the earlier valid action must remain unaffected by the rejected put"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
