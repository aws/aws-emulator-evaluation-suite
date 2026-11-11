"""delete-auto-scaling-group-concurrent-contention-fails."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-auto-scaling-group-concurrent-contention-fails"
GROUP = "concurrency"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent ForceDelete calls on one group are each accepted or, once the group is gone,
    answer the not-found ValidationError; none fails with ResourceContention, and the group is
    gone at the end. A fresh, unraced group deleted alongside is the positive control."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami_id = _get_amazon_linux_ami(ctx)
    az = _get_az(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        Tags=_asg_tags(asg_name),
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    # Defensive cleanup in case every racer below unexpectedly errors out.
    ctx.on_cleanup(lambda: _delete_if_present(autoscaling, asg_name))

    def racer(_i: int):
        try:
            autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
            return ("ok", None)
        except ClientError as err:
            return ("error", (err.response["Error"]["Code"], err.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(racer, range(8)))

    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o[1] for o in outcomes if o[0] == "error"]

    # A racer the target serves after the group is already gone gets the documented not-found
    # answer; no racer fails with ResourceContention or any other code.
    gone = ("ValidationError", f"AutoScalingGroup name not found - AutoScalingGroup '{asg_name}' not found")
    assert successes, f"at least one racing ForceDelete is accepted; failures {failures!r}"
    assert all(f == gone for f in failures), (
        f"every racing ForceDelete is accepted or answers {gone!r} once the group is gone; "
        f"got {failures!r}"
    )

    # Final state: the group is gone, exactly once, no corruption -- poll
    # because deletion of an ASG (even an empty one) is asynchronous.
    _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ],
        lambda groups: groups == [],
        timeout_s=60,
        interval_s=3,
    )

    # Positive control: a fresh group deletes cleanly outside of any race.
    control_name = ctx.unique_name("sim2real-behav-asg-control-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=control_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        Tags=_asg_tags(control_name),
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    autoscaling.delete_auto_scaling_group(AutoScalingGroupName=control_name, ForceDelete=True)
    control_groups = _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[control_name])[
            "AutoScalingGroups"
        ],
        lambda groups: groups == [],
        timeout_s=60,
        interval_s=3,
    )
    assert control_groups == [], (
        f"positive control: an unraced delete must fully remove the group, got {control_groups!r}"
    )


# ===== helpers =====
_MANAGED_TAGS = {"sim2real": "as-depth", "sim2real:managed": "true"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _asg_tags(asg_name: str) -> list[dict]:
    return [
        {"ResourceId": asg_name, "ResourceType": "auto-scaling-group", "Key": k, "Value": v, "PropagateAtLaunch": False}
        for k, v in _MANAGED_TAGS.items()
    ]


def _delete_if_present(autoscaling, asg_name: str) -> None:
    """Force-delete the group if it still exists; only its "not found" ValidationError means gone."""
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    if groups:
        try:
            autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
                raise


def _get_amazon_linux_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _get_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    return ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"][0]["ZoneName"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


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

