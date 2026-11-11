"""delete-nonexistent-group-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-nonexistent-group-fails"
GROUP = 'error-semantics'
SERVICES = ['autoscaling']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAutoScalingGroup on a name that never existed raises ValidationError (it is NOT
    idempotent), and a real, unrelated group is left untouched by the failed call."""
    as_ = ctx.client("autoscaling")
    group_name = _create_shell_asg(ctx, min_size=0, max_size=0, desired=0)
    bogus = ctx.unique_name("sim2real-behav-as-missing-")

    before = {
        g["AutoScalingGroupName"]
        for g in as_.describe_auto_scaling_groups(
            AutoScalingGroupNames=[group_name, bogus]
        )["AutoScalingGroups"]
    }
    assert before == {group_name}, f"expected only the real group to exist, got {before}"

    try:
        as_.delete_auto_scaling_group(AutoScalingGroupName=bogus)
    except ClientError as exc:
        error = exc.response.get("Error", {})
    else:
        raise AssertionError("DeleteAutoScalingGroup on an unknown group succeeded; real AWS rejects it")
    code = error.get("Code")
    message = error.get("Message")
    assert code == "ValidationError", f"expected ValidationError for unknown group, got {code}"
    expected = f"AutoScalingGroup name not found - AutoScalingGroup '{bogus}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = {
        g["AutoScalingGroupName"]
        for g in as_.describe_auto_scaling_groups(
            AutoScalingGroupNames=[group_name, bogus]
        )["AutoScalingGroups"]
    }
    assert after == {group_name}, (
        f"a rejected delete of an unknown group must not change unrelated group state, got {after}"
    )


def _get_launch_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
    return resp["Parameter"]["Value"]


def _create_shell_asg(ctx, min_size: int, max_size: int, desired: int) -> str:
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami = _get_launch_ami(ctx)
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
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        AvailabilityZones=[az],
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
