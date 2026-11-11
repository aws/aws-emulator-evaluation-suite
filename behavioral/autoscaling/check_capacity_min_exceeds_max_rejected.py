"""capacity-min-exceeds-max-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-min-exceeds-max-rejected"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAutoScalingGroup with MinSize greater than MaxSize is rejected with
    ValidationError, no group is created as a result, and an otherwise-identical
    valid request still succeeds (positive control)."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    az = _first_available_az(ec2, ctx=ctx)
    ami_id = _latest_al2_ami(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    bad_asg = ctx.unique_name("sim2real-behav-asg-bad-")
    code, message = _client_error(
        lambda: autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=bad_asg,
            LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
            MinSize=5,
            MaxSize=1,
            DesiredCapacity=0,
            AvailabilityZones=[az],
            VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message == "Max bound, 1, must be greater than or equal to min bound, 5", f"expected the exact refusal message, got {message!r}"

    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[bad_asg])[
        "AutoScalingGroups"
    ]
    assert groups == [], "rejected group must not have been created"

    good_asg = ctx.unique_name("sim2real-behav-asg-good-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=good_asg,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=good_asg, ForceDelete=True)
    )
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[good_asg])[
        "AutoScalingGroups"
    ]
    assert len(groups) == 1, "positive control group should have been created"


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


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
