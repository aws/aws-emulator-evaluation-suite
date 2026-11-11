"""asg-minsize-greater-than-maxsize-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "asg-minsize-greater-than-maxsize-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAutoScalingGroup rejects MinSize > MaxSize with ValidationError, leaves no group
    behind, and a same-shaped valid request (positive control) still succeeds."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _valid_ami(ctx), "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    bad_name = ctx.unique_name("sim2real-behav-asg-bad-")
    # Registered before the call: if an over-permissive target accepts the inverted bounds
    # anyway, the group it creates must still be cleaned up.
    ctx.on_cleanup(lambda: _delete_group_if_present(autoscaling, bad_name))

    def _create_bad():
        autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=bad_name,
            MinSize=5,
            MaxSize=2,
            DesiredCapacity=0,
            LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
            AvailabilityZones=[ctx.network().availability_zones[0]],
            Tags=_tags_kv(propagate_at_launch=True),
            VPCZoneIdentifier=_network_zone_subnets(ctx, [ctx.network().availability_zones[0]]),
        )

    code, message = _client_error(_create_bad)
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message == "Max bound, 2, must be greater than or equal to min bound, 5", f"expected the exact refusal message, got {message!r}"

    # Effect absent: the invalid group must not exist.
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[bad_name])[
        "AutoScalingGroups"
    ]
    assert groups == [], f"rejected group should not exist, but found {groups!r}"

    # Positive control: an otherwise-identical, valid request still succeeds.
    good_name = ctx.unique_name("sim2real-behav-asg-good-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=good_name,
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        AvailabilityZones=[ctx.network().availability_zones[0]],
        Tags=_tags_kv(propagate_at_launch=True),
        VPCZoneIdentifier=_network_zone_subnets(ctx, [ctx.network().availability_zones[0]]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=good_name, ForceDelete=True
        )
    )
    good_groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[good_name])[
        "AutoScalingGroups"
    ]
    assert len(good_groups) == 1, f"expected exactly 1 group named {good_name!r}, got {good_groups!r}"
    assert good_groups[0]["MinSize"] == 0, f"expected MinSize 0, got {good_groups[0]['MinSize']!r}"
    assert good_groups[0]["MaxSize"] == 2, f"expected MaxSize 2, got {good_groups[0]['MaxSize']!r}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_group_if_present(autoscaling, name):
    """ForceDelete the group; a group that was never created is already clean."""
    from botocore.exceptions import ClientError

    try:
        autoscaling.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    except ClientError as err:
        error = err.response["Error"]
        if error["Code"] != "ValidationError" or "not found" not in error.get("Message", ""):
            raise


def _tags_kv(*, propagate_at_launch=None):
    tag = {"Key": "sim2real", "Value": CHECK}
    if propagate_at_launch is not None:
        tag["PropagateAtLaunch"] = propagate_at_launch
    return [tag]


def _valid_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


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
