"""describe-account-limits-reflects-server-enforced-caps."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-account-limits-reflects-server-enforced-caps"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAccountLimits.NumberOfAutoScalingGroups matches the paginated group count while the
    groups this check creates are listed and after they are deleted, never exceeding
    MaxNumberOfAutoScalingGroups, which stays put."""
    asg = ctx.client("autoscaling")
    max_groups = asg.describe_account_limits()["MaxNumberOfAutoScalingGroups"]
    _settled(ctx)

    lt_name = _create_launch_template(ctx, ami_id=_get_al2_ami(ctx))
    zone = ctx.network().availability_zones[0]
    created = []
    for _ in range(2):
        name = ctx.unique_name("sim2real-behav-asg-")
        asg.create_auto_scaling_group(
            AutoScalingGroupName=name,
            LaunchTemplate={"LaunchTemplateName": lt_name},
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            VPCZoneIdentifier=_network_zone_subnets(ctx, [zone]),
            Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
        )
        created.append(name)
        ctx.on_cleanup(lambda n=name: _delete_asg_force(ctx, n))

    raised = _settled(ctx, present=created)
    limits = asg.describe_account_limits()
    assert limits["MaxNumberOfAutoScalingGroups"] == max_groups, (
        f"MaxNumberOfAutoScalingGroups moved from {max_groups} to "
        f"{limits['MaxNumberOfAutoScalingGroups']} while only groups were created"
    )
    assert raised <= max_groups, (
        f"NumberOfAutoScalingGroups {raised} exceeds MaxNumberOfAutoScalingGroups {max_groups}"
    )

    for name in created:
        _delete_asg_force(ctx, name)
    _settled(ctx, absent=created)


_SETTLE_TIMEOUT_S = 180


def _settled(ctx, present=(), absent=()):
    """Poll until DescribeAccountLimits agrees with the paginated count, the listing holds every
    group in ``present`` and none in ``absent``; return the reported count."""
    asg = ctx.client("autoscaling")
    deadline = time.monotonic() + _SETTLE_TIMEOUT_S
    while True:
        reported = asg.describe_account_limits()["NumberOfAutoScalingGroups"]
        names = _list_group_names(ctx)
        if (reported == len(names) and all(n in names for n in present)
                and not any(n in names for n in absent)):
            return reported
        if time.monotonic() > deadline:
            raise AssertionError(
                f"NumberOfAutoScalingGroups {reported} never settled to the paginated count "
                f"{len(names)} with groups {list(present)} listed and {list(absent)} gone "
                f"within {_SETTLE_TIMEOUT_S}s"
            )
        time.sleep(5)


def _network_zone_subnets(ctx, zones) -> str:
    """The shared network's subnets in `zones`, comma-separated for VPCZoneIdentifier."""
    by_zone = ctx.network().subnets
    missing = [z for z in zones if z not in by_zone]
    if missing:
        raise AssertionError(f"the run's shared network has no subnet in {missing}")
    return ",".join(by_zone[z] for z in zones)


def _list_group_names(ctx) -> set:
    asg = ctx.client("autoscaling")
    paginator = asg.get_paginator("describe_auto_scaling_groups")
    return {g["AutoScalingGroupName"] for page in paginator.paginate() for g in page["AutoScalingGroups"]}


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _delete_asg_force(ctx, name: str) -> None:
    asg = ctx.client("autoscaling")
    for _ in range(20):
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ScalingActivityInProgress", "ResourceContention", "ResourceInUse"):
                time.sleep(5)
                continue
            if code == "ValidationError":
                return
            raise
    raise AssertionError(f"DeleteAutoScalingGroup kept failing transiently for {name!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
