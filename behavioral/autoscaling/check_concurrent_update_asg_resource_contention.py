"""concurrent-update-asg-resource-contention."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-asg-resource-contention"
GROUP = "concurrency"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Overlapping UpdateAutoScalingGroup calls on one group either succeed or fail with
    ResourceContention, and the final MaxSize is one of the submitted values."""
    asg = ctx.client("autoscaling")
    ami_id = _get_al2_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id=ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        AvailabilityZones=[ctx.network().availability_zones[0]],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [ctx.network().availability_zones[0]]),
    )
    ctx.on_cleanup(lambda: _delete_asg_force(ctx, group_name))

    candidate_values = [5, 6, 7, 8, 9, 10]

    def _update(max_size: int):
        try:
            asg.update_auto_scaling_group(AutoScalingGroupName=group_name, MaxSize=max_size)
            return ("ok", max_size)
        except ClientError as err:
            return ("error", err.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=len(candidate_values)) as pool:
        futures = [pool.submit(_update, v) for v in candidate_values]
        results = [f.result() for f in as_completed(futures)]

    succeeded = [v for kind, v in results if kind == "ok"]
    assert succeeded, "no concurrent UpdateAutoScalingGroup call succeeded at all"
    for kind, value in results:
        if kind == "error":
            assert value == "ResourceContention", (
                f"a losing concurrent writer failed with {value!r}, "
                "expected ResourceContention specifically"
            )

    final = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
        "AutoScalingGroups"
    ][0]
    assert final["MaxSize"] in candidate_values, (
        f"final MaxSize {final['MaxSize']} is not one of the submitted values "
        f"{candidate_values} -- indicates corrupted/partially-applied state"
    )


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _delete_asg_force(ctx, name: str) -> None:
    asg = ctx.client("autoscaling")
    for _ in range(20):
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ScalingActivityInProgress", "ResourceContention", "ResourceInUse"):
                time.sleep(5)
                continue
            if code == "ValidationError":
                return
            raise


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
