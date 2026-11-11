"""describe-account-limits-concurrent-consistency."""
from __future__ import annotations

import concurrent.futures

from behavioral_harness import tags

CHECK = "describe-account-limits-concurrent-consistency"
GROUP = "concurrency"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A burst of concurrent DescribeAccountLimits calls returns the same limits on every call and
    usage counts that include the check's own group, with no spurious ResourceContentionFault
    surfacing under normal (non-mutating) concurrent load."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    az = _first_available_az(ec2, ctx=ctx)
    ami_id = _latest_al2_ami(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )

    def _snapshot(_):
        resp = autoscaling.describe_account_limits()
        return (
            resp["MaxNumberOfAutoScalingGroups"],
            resp["MaxNumberOfLaunchConfigurations"],
            resp["NumberOfAutoScalingGroups"],
            resp["NumberOfLaunchConfigurations"],
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        snapshots = list(pool.map(_snapshot, range(10)))

    # The quotas are graded exactly; the usage counters are account-wide and move with any other
    # caller's groups, so each snapshot is graded only on counting this check's own group.
    first = snapshots[0]
    for snap in snapshots[1:]:
        assert snap[:2] == first[:2], (
            f"inconsistent account limits reported under concurrent burst: {first} vs {snap}"
        )
    for snap in snapshots:
        assert snap[2] >= 1, f"NumberOfAutoScalingGroups does not count this check's own group: {snap}"
        assert isinstance(snap[3], int), f"NumberOfLaunchConfigurations is not an integer: {snap}"


def _first_available_az(ec2, *, ctx) -> str:
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"]
    if not zones:
        raise AssertionError("no available availability zones in this region")
    return zones[0]["ZoneName"]


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]


def _network_zone_subnets(ctx, zones) -> str:
    """The shared network's subnets in `zones`, comma-separated for VPCZoneIdentifier."""
    by_zone = ctx.network().subnets
    missing = [z for z in zones if z not in by_zone]
    if missing:
        raise AssertionError(f"the run's shared network has no subnet in {missing}")
    return ",".join(by_zone[z] for z in zones)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
