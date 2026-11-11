"""metrics-emitted-after-scaling-activity."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "metrics-emitted-after-scaling-activity"
GROUP = "telemetry"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With metrics collection enabled, an actual capacity change produces a real
    scaling activity (not just a config toggle) whose Cause/StatusCode reflect the
    change, and the enabled-metrics subset survives the activity unchanged."""
    autoscaling = ctx.client("autoscaling")

    _vpc_id, subnet_ids, sg_id = _default_vpc_subnets(ctx)
    ami = _al2_ami_id(ctx)

    lt_name = ctx.unique_name("sim2real-lt-")
    ec2 = ctx.client("ec2")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro", "SecurityGroupIds": [sg_id]},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-behav", "Value": lt_name}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name, LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0, MaxSize=1, DesiredCapacity=0,
        VPCZoneIdentifier=subnet_ids[0], HealthCheckType="EC2", HealthCheckGracePeriod=60,
        Tags=[
            {
                "ResourceId": asg_name,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real-behav",
                "Value": asg_name,
                "PropagateAtLaunch": False,
            }
        ],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))

    tracked_metrics = ["GroupDesiredCapacity", "GroupTotalInstances"]
    autoscaling.enable_metrics_collection(
        AutoScalingGroupName=asg_name, Granularity="1Minute", Metrics=tracked_metrics,
    )
    ctx.on_cleanup(lambda: autoscaling.disable_metrics_collection(AutoScalingGroupName=asg_name))

    marker = time.time()
    autoscaling.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False)

    activities = _poll_until(
        lambda: autoscaling.describe_scaling_activities(AutoScalingGroupName=asg_name)["Activities"],
        lambda acts: any(
            a["StatusCode"] == "Successful" and "0 to 1" in a.get("Cause", "")
            for a in acts
        ),
        timeout_s=180.0, interval_s=5.0,
    )
    matching = [a for a in activities if a["StatusCode"] == "Successful" and "0 to 1" in a.get("Cause", "")]
    assert matching, (
        f"expected a Successful scaling Activity whose Cause mentions '0 to 1'; "
        f"got activities={activities!r}"
    )
    got_start = matching[0]["StartTime"].timestamp()
    assert got_start >= marker - 5, (
        f"expected matching activity StartTime >= {marker - 5} (set_desired_capacity call time); "
        f"got {got_start}"
    )

    final_group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
    assert final_group["DesiredCapacity"] == 1, (
        f"expected DesiredCapacity == 1 after set_desired_capacity; got {final_group['DesiredCapacity']!r}"
    )
    got_enabled = {m["Metric"] for m in final_group["EnabledMetrics"]}
    assert got_enabled == set(tracked_metrics), (
        f"expected EnabledMetrics to still be exactly {set(tracked_metrics)!r} after the scaling "
        f"activity; got {got_enabled!r}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _al2_ami_id(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"]["Value"]


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, [s["SubnetId"] for s in subnets], sg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
