"""describe-scaling-activities-invalid-next-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-scaling-activities-invalid-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeScalingActivities succeeds without a token but rejects a malformed NextToken with
    InvalidNextToken rather than ignoring it or returning an empty page."""
    autoscaling = ctx.client("autoscaling")
    # AWS validates the token only when the account holds a group, so create one.
    group_name = _create_shell_asg(ctx)

    # Positive control: a plain call (no token) succeeds and returns a page.
    ok = autoscaling.describe_scaling_activities(AutoScalingGroupName=group_name, MaxRecords=1)
    assert "Activities" in ok, f"expected a well-formed DescribeScalingActivities response, got keys {list(ok)}"

    bogus_token = "not-a-real-pagination-token-xyz"
    error = _error(
        lambda: autoscaling.describe_scaling_activities(AutoScalingGroupName=group_name, NextToken=bogus_token)
    )
    code = error.get("Code")
    assert code == "InvalidNextToken", f"expected InvalidNextToken, got {code}"
    expected_message = f"The token '{bogus_token}' was invalid"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


def _create_shell_asg(ctx) -> str:
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami = ctx.client("ssm").get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    lt_name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))
    az = ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"][0]["ZoneName"]
    group_name = ctx.unique_name("sim2real-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True))
    return group_name


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so accepting a
    malformed NextToken is not reported as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


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
