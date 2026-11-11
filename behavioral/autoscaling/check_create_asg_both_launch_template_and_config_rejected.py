"""create-asg-both-launch-template-and-config-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-asg-both-launch-template-and-config-rejected"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAutoScalingGroup with both LaunchTemplate and LaunchConfigurationName fails with
    ValidationError and creates no group; the same call with only LaunchTemplate succeeds."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    ami_id = _get_amazon_linux_ami(ctx)
    az = _get_az(ctx)

    lc_name = ctx.unique_name("sim2real-behav-lc-")

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    # Registered first so a wrongly accepted create is still cleaned up.
    ctx.on_cleanup(lambda: _safe_call(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    ))

    # The mutual-exclusion check runs before existence checks, so lc_name need not exist.
    code, message = _client_error(
        lambda: autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            LaunchConfigurationName=lc_name,
            LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
            MinSize=0,
            MaxSize=1,
            AvailabilityZones=[az],
            VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message == (
        "Valid requests must contain either LaunchTemplate, LaunchConfigurationName, InstanceId "
        "or MixedInstancesPolicy parameter."
    ), f"expected the exact refusal message, got {message!r}"

    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert groups == [], "ASG should not exist after the conflicting create was rejected"

    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=[az],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert len(groups) == 1 and groups[0]["AutoScalingGroupName"] == asg_name, (
        f"expected exactly one group named {asg_name!r} once the identical call succeeded "
        f"with the conflicting LaunchConfigurationName dropped, got {groups!r}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. Success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_call(fn):
    """Run a teardown delete; only a not-found error means already gone, anything else raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] in _NOT_FOUND_CODES:
            return
        if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
            raise


_NOT_FOUND_CODES = ("InvalidLaunchTemplateName.NotFoundException", "InvalidLaunchTemplateId.NotFound")


def _get_amazon_linux_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _get_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    return ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"][0]["ZoneName"]


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
