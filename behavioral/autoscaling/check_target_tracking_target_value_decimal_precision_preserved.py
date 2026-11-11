"""target-tracking-target-value-decimal-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "target-tracking-target-value-decimal-precision-preserved"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A floating-point TargetValue in a TargetTrackingConfiguration round-trips
    through PutScalingPolicy/DescribePolicies with full decimal precision -- the
    server does not round it to a coarser value."""
    asgc = ctx.client("autoscaling")

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    lt_id = _create_launch_template(ctx)
    asgc.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        AvailabilityZones=[_first_az(ctx)],
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        Tags=[
            {
                "ResourceId": asg_name,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real:managed",
                "Value": "true",
                "PropagateAtLaunch": False,
            },
        ],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [_first_az(ctx)]),
    )
    ctx.on_cleanup(lambda: asgc.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))

    target_value = 62.34567
    policy_name = ctx.unique_name("sim2real-behav-tt-policy-")
    asgc.put_scaling_policy(
        AutoScalingGroupName=asg_name,
        PolicyName=policy_name,
        PolicyType="TargetTrackingScaling",
        TargetTrackingConfiguration={
            "PredefinedMetricSpecification": {"PredefinedMetricType": "ASGAverageCPUUtilization"},
            "TargetValue": target_value,
        },
    )
    ctx.on_cleanup(lambda: asgc.delete_policy(AutoScalingGroupName=asg_name, PolicyName=policy_name))

    policy = asgc.describe_policies(AutoScalingGroupName=asg_name, PolicyNames=[policy_name])["ScalingPolicies"][0]
    returned_value = policy["TargetTrackingConfiguration"]["TargetValue"]
    assert returned_value == target_value, f"TargetValue precision lost: {returned_value!r} != {target_value!r}"


def _create_launch_template(ctx) -> str:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami_id = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"][
        "Value"
    ]
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]},
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _first_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
        "AvailabilityZones"
    ]
    return zones[0]["ZoneName"]


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
