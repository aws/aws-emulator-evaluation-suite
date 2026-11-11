"""metrics-collection-emits-after-scaling-activity."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "metrics-collection-emits-after-scaling-activity"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With metrics collection on, an executed scaling policy yields a Successful Activity.

    DesiredCapacity and Instances grow to match, and EnabledMetrics still lists the full metric
    catalog afterwards. One real t3.micro is the cheapest shape that produces the Activity.
    """
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    az = _first_available_az(ec2, ctx=ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )

    def _cleanup_asg():
        autoscaling.update_auto_scaling_group(
            AutoScalingGroupName=asg_name, MinSize=0, DesiredCapacity=0
        )
        autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)

    ctx.on_cleanup(_cleanup_asg)

    catalog = {m["Metric"] for m in autoscaling.describe_metric_collection_types()["Metrics"]}
    autoscaling.enable_metrics_collection(AutoScalingGroupName=asg_name, Granularity="1Minute")
    ctx.on_cleanup(lambda: autoscaling.disable_metrics_collection(AutoScalingGroupName=asg_name))

    policy_name = ctx.unique_name("sim2real-behav-policy-")
    autoscaling.put_scaling_policy(
        AutoScalingGroupName=asg_name,
        PolicyName=policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
        Cooldown=0,
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_policy(AutoScalingGroupName=asg_name, PolicyName=policy_name)
    )

    autoscaling.execute_policy(
        AutoScalingGroupName=asg_name, PolicyName=policy_name, HonorCooldown=False
    )

    activity = _poll_until_successful_activity(ctx, asg_name, timeout_s=180.0)
    assert activity["StatusCode"] == "Successful", f"expected Successful, got {activity['StatusCode']}"

    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group["DesiredCapacity"] == 1, f"expected DesiredCapacity=1, got {group['DesiredCapacity']}"
    assert len(group["Instances"]) >= 1, f"expected >=1 instance, got {len(group['Instances'])}"

    enabled_after_activity = {m["Metric"] for m in group["EnabledMetrics"]}
    assert enabled_after_activity == catalog, (
        f"metrics collection did not survive the scaling activity intact: "
        f"expected the full catalog {sorted(catalog)}, got {sorted(enabled_after_activity)}"
    )


def _first_available_az(ec2, *, ctx) -> str:
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"]
    if not zones:
        raise AssertionError("no available availability zones in this region")
    return zones[0]["ZoneName"]


def _poll_until_successful_activity(ctx, asg_name: str, timeout_s: float = 180.0):
    autoscaling = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        activities = autoscaling.describe_scaling_activities(AutoScalingGroupName=asg_name)[
            "Activities"
        ]
        for act in activities:
            last = act
            if act.get("StatusCode") == "Successful":
                return act
            if act.get("StatusCode") == "Failed":
                raise AssertionError(f"scaling activity failed: {act.get('StatusMessage')}")
        time.sleep(3.0)
    raise AssertionError(f"no successful scaling activity within {timeout_s}s; last={last}")


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
