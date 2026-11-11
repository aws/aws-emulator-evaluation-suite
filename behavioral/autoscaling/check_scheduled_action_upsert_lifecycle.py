"""scheduled-action-upsert-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduled-action-upsert-lifecycle"
GROUP = 'scheduled-actions'
SERVICES = ['autoscaling']

_AL2023_SSM_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
# DescribeImages fallback when the execution role has no ssm:GetParameter.
_AMI_NAME_PATTERNS = (
    "al2023-ami-2023.*-kernel-6.1-x86_64",
    "al2023-ami-*-x86_64",
    "amzn2-ami-hvm-*-x86_64-gp2",
)
_CANDIDATE_INSTANCE_TYPES = ("t3.micro", "t2.micro", "t3a.micro")
# A tag set on every resource this check creates. It is also the "unrelated tag" a
# targeted DeleteTags must not touch.
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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutScheduledUpdateGroupAction is an upsert keyed by name; delete removes it."""
    as_ = ctx.client("autoscaling")
    env = _discover_env(ctx)

    name = _make_group(ctx, as_, env, min_size=0, max_size=4, desired_capacity=0)
    action_name = ctx.unique_name("sim2real-behav-asg-sched-")

    as_.put_scheduled_update_group_action(
        AutoScalingGroupName=name,
        ScheduledActionName=action_name,
        Recurrence="30 4 * * *",
        MinSize=1,
        MaxSize=3,
        DesiredCapacity=2,
        TimeZone="UTC",
    )
    def _drop_action():
        try:
            as_.delete_scheduled_action(AutoScalingGroupName=name, ScheduledActionName=action_name)
        except ClientError as exc:
            # The body deletes the action itself; teardown only covers an early failure.
            if exc.response.get("Error", {}).get("Message") != "Scheduled action name not found":
                raise

    ctx.on_cleanup(_drop_action)

    actions = as_.describe_scheduled_actions(
        AutoScalingGroupName=name, ScheduledActionNames=[action_name]
    )["ScheduledUpdateGroupActions"]
    assert len(actions) == 1, actions
    action = actions[0]
    assert (action["MinSize"], action["MaxSize"], action["DesiredCapacity"]) == (1, 3, 2), action
    assert action["Recurrence"] == "30 4 * * *", action
    assert action["TimeZone"] == "UTC", action
    assert action["ScheduledActionARN"].startswith("arn:aws:autoscaling:"), action
    assert action.get("StartTime") is not None, (
        "a recurring action must expose its next occurrence"
    )

    # Same name again updates in place rather than creating a second action.
    as_.put_scheduled_update_group_action(
        AutoScalingGroupName=name,
        ScheduledActionName=action_name,
        Recurrence="30 4 * * *",
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=1,
    )
    updated = as_.describe_scheduled_actions(
        AutoScalingGroupName=name, ScheduledActionNames=[action_name]
    )["ScheduledUpdateGroupActions"]
    assert len(updated) == 1, f"upsert must not duplicate the action: {updated}"
    assert (
        updated[0]["MinSize"],
        updated[0]["MaxSize"],
        updated[0]["DesiredCapacity"],
    ) == (0, 2, 1), updated[0]

    as_.delete_scheduled_action(AutoScalingGroupName=name, ScheduledActionName=action_name)
    assert (
        as_.describe_scheduled_actions(
            AutoScalingGroupName=name, ScheduledActionNames=[action_name]
        )["ScheduledUpdateGroupActions"]
        == []
    ), "scheduled action must be gone after delete"

    # The delete is not just absent from the list -- the id is unusable: a repeat delete
    # against the now-gone name fails with the same ValidationError real AWS raises for a
    # name that was never created.
    try:
        as_.delete_scheduled_action(AutoScalingGroupName=name, ScheduledActionName=action_name)
        raise AssertionError("expected a second delete of the same action to raise ValidationError")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ValidationError", f"expected ValidationError, got {code}"
        assert message == "Scheduled action name not found", (
            f"unexpected ValidationError message: {message!r}"
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
