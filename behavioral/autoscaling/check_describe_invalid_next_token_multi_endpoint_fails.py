"""describe-invalid-next-token-multi-endpoint-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-invalid-next-token-multi-endpoint-fails"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]

BOGUS_TOKEN = "sim2real-not-a-real-next-token-xyz123"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A malformed NextToken fails validation on DescribeAutoScalingInstances (InvalidNextToken)
    and on DescribeLoadBalancers / DescribeTrafficSources (ValidationError when sent without
    MaxRecords); each endpoint's own error code and message are pinned."""
    asg = ctx.client("autoscaling")
    group_name = _create_shell_asg(ctx, min_size=0, max_size=1, desired=0)

    err_instances = _error(lambda: asg.describe_auto_scaling_instances(NextToken=BOGUS_TOKEN))
    code_instances = err_instances.get("Code")
    assert code_instances == "InvalidNextToken", f"DescribeAutoScalingInstances: expected InvalidNextToken, got {code_instances}"
    expected_instances = f"The token '{BOGUS_TOKEN}' is invalid"
    assert err_instances.get("Message") == expected_instances, (
        f"DescribeAutoScalingInstances: expected message {expected_instances!r}, got {err_instances.get('Message')!r}"
    )

    no_max_records = "Cannot specify NextToken without MaxRecords"
    err_lbs = _error(
        lambda: asg.describe_load_balancers(AutoScalingGroupName=group_name, NextToken=BOGUS_TOKEN)
    )
    code_lbs = err_lbs.get("Code")
    assert code_lbs == "ValidationError", f"DescribeLoadBalancers: expected ValidationError, got {code_lbs}"
    assert err_lbs.get("Message") == no_max_records, (
        f"DescribeLoadBalancers: expected message {no_max_records!r}, got {err_lbs.get('Message')!r}"
    )

    err_traffic = _error(
        lambda: asg.describe_traffic_sources(AutoScalingGroupName=group_name, NextToken=BOGUS_TOKEN)
    )
    code_traffic = err_traffic.get("Code")
    assert code_traffic == "ValidationError", f"DescribeTrafficSources: expected ValidationError, got {code_traffic}"
    assert err_traffic.get("Message") == no_max_records, (
        f"DescribeTrafficSources: expected message {no_max_records!r}, got {err_traffic.get('Message')!r}"
    )

    # Sanity: the SAME calls without a NextToken succeed normally on the fresh group.
    asg.describe_auto_scaling_instances()
    asg.describe_load_balancers(AutoScalingGroupName=group_name)
    asg.describe_traffic_sources(AutoScalingGroupName=group_name)


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so accepting a
    malformed NextToken is not reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _get_launch_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
    return resp["Parameter"]["Value"]


def _create_shell_asg(ctx, min_size: int, max_size: int, desired: int) -> str:
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami = _get_launch_ami(ctx)
    # AWS rejects CreateLaunchConfiguration for many accounts ("Launch Configuration
    # creation operation is not available"), so a launch template is used.
    lt_name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    az = ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"][0]["ZoneName"]
    group_name = ctx.unique_name("sim2real-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        AvailabilityZones=[az],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True))
    return group_name


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
