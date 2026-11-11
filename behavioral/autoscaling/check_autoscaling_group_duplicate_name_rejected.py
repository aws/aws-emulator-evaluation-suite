"""autoscaling-group-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "autoscaling-group-duplicate-name-rejected"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAutoScalingGroup with a name in use is rejected with AlreadyExists and leaves the
    original group untouched; deleting the original frees the name for reuse, and a fresh name
    succeeds."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    az = _get_one_az(ctx)

    lt_name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _get_ami(ctx), "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    def _create_group(name):
        autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=name,
            LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
            MinSize=0,
            MaxSize=1,
            DesiredCapacity=0,
            AvailabilityZones=[az],
            Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
            VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
        )

    asg_name = ctx.unique_name("sim2real-asg-")
    _create_group(asg_name)
    asg_names_to_delete = [asg_name]

    def _cleanup_groups():
        failed = []
        for n in asg_names_to_delete:
            try:
                autoscaling.delete_auto_scaling_group(AutoScalingGroupName=n, ForceDelete=True)
            except ClientError as exc:
                err = exc.response["Error"]
                if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
                    failed.append(f"{n}: {err['Code']} {err.get('Message')}")
        if failed:
            raise AssertionError(f"Auto Scaling group delete failed: {failed}")

    ctx.on_cleanup(_cleanup_groups)

    # Negative: re-creating with the same name but different sizing must be rejected,
    # and the original group's sizing must be untouched by the rejected attempt.
    code, message = _client_error(
        lambda: autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
            MinSize=5,
            MaxSize=10,
            DesiredCapacity=7,
            AvailabilityZones=[az],
            VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
        )
    )
    assert code == "AlreadyExists", (
        f"expected AlreadyExists re-creating {asg_name!r}, got {code!r}"
    )
    assert message == (
        f"AutoScalingGroup by this name already exists - A group with the name {asg_name} already exists"
    ), f"expected the exact refusal message, got {message!r}"

    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group["MinSize"] == 0, f"MinSize mutated by rejected create: {group['MinSize']}"
    assert group["MaxSize"] == 1, f"MaxSize mutated by rejected create: {group['MaxSize']}"
    assert group["DesiredCapacity"] == 0, f"DesiredCapacity mutated by rejected create: {group['DesiredCapacity']}"

    # Restore: deleting the original frees the name. The identical name AWS just refused
    # to reuse must become available again once nothing is holding it — not permanently
    # blocked by the earlier rejection.
    autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ],
        lambda groups: groups == [],
        timeout_s=90,
        description=f"deletion of {asg_name!r} to become visible",
    )
    _create_group(asg_name)
    reused = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert len(reused) == 1, f"expected the freed name {asg_name!r} to be reusable, got {reused}"

    # Positive control: a fresh, unused name succeeds.
    other_name = ctx.unique_name("sim2real-asg-other-")
    _create_group(other_name)
    asg_names_to_delete.append(other_name)
    created = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[other_name])[
        "AutoScalingGroups"
    ]
    assert len(created) == 1, f"expected the freshly-named group to exist, got {created}"


# ===== helpers =====

def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, because accepting a call AWS refuses is itself the failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _get_one_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"]
    assert azs, "no available availability zones in region"
    return azs[0]["ZoneName"]


def _get_ami(ctx) -> str:
    """Resolve a real, currently-valid AMI id via the public SSM parameter for the
    latest Amazon Linux 2 AMI (avoids hardcoding an AMI id that AWS will reject
    as malformed/nonexistent)."""
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
