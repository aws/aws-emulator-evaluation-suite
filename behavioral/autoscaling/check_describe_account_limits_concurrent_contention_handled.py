"""describe-account-limits-concurrent-contention-handled."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-account-limits-concurrent-contention-handled"
GROUP = "concurrency"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent DescribeAccountLimits calls, racing group create/delete mutations, return
    consistent limits (non-negative integers, Number <= Max) or ResourceContention, never
    partial or malformed data."""
    autoscaling = ctx.client("autoscaling")
    az = _first_az(ctx)
    lt_name = _create_dummy_launch_template(ctx)

    def _mutate(_: int) -> None:
        name = ctx.unique_name("sim2real-asg-mut-")
        try:
            autoscaling.create_auto_scaling_group(
                AutoScalingGroupName=name,
                LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
                MinSize=0,
                MaxSize=0,
                DesiredCapacity=0,
                AvailabilityZones=[az],
                Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
                VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
            )
        except ClientError:
            return
        ctx.on_cleanup(
            lambda: autoscaling.delete_auto_scaling_group(
                AutoScalingGroupName=name, ForceDelete=True
            )
        )
        try:
            autoscaling.delete_auto_scaling_group(
                AutoScalingGroupName=name, ForceDelete=True
            )
        except ClientError:
            pass

    def _describe(_: int) -> tuple[str, object]:
        try:
            return ("ok", autoscaling.describe_account_limits())
        except ClientError as exc:
            return ("err", exc.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=16) as pool:
        mutate_futures = [pool.submit(_mutate, i) for i in range(4)]
        describe_futures = [pool.submit(_describe, i) for i in range(10)]
        for future in mutate_futures:
            future.result()
        results = [future.result() for future in describe_futures]

    assert len(results) == 10, f"expected 10 describe_account_limits results, got {len(results)}"
    for kind, payload in results:
        if kind == "err":
            assert payload == "ResourceContention", payload
            continue
        for key in (
            "MaxNumberOfAutoScalingGroups",
            "MaxNumberOfLaunchConfigurations",
            "NumberOfAutoScalingGroups",
            "NumberOfLaunchConfigurations",
        ):
            assert isinstance(payload[key], int) and payload[key] >= 0, payload
        assert payload["NumberOfAutoScalingGroups"] <= payload["MaxNumberOfAutoScalingGroups"], (
            f"NumberOfAutoScalingGroups {payload['NumberOfAutoScalingGroups']} exceeds "
            f"MaxNumberOfAutoScalingGroups {payload['MaxNumberOfAutoScalingGroups']}"
        )
        assert (
            payload["NumberOfLaunchConfigurations"]
            <= payload["MaxNumberOfLaunchConfigurations"]
        ), (
            f"NumberOfLaunchConfigurations {payload['NumberOfLaunchConfigurations']} exceeds "
            f"MaxNumberOfLaunchConfigurations {payload['MaxNumberOfLaunchConfigurations']}"
        )


def _first_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"]
    return zones[0]["ZoneName"]


def _create_dummy_launch_template(ctx) -> str:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


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
