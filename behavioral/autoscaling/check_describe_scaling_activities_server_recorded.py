"""describe-scaling-activities-server-recorded."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-scaling-activities-server-recorded"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetDesiredCapacity and TerminateInstanceInAutoScalingGroup each produce a server-generated
    scaling activity with a unique ActivityId, a Cause, a valid StatusCode and a StartTime."""
    asg = ctx.client("autoscaling")
    subnet_id = _get_default_subnet(ctx)
    ami_id = _get_al2_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id=ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: _delete_asg_force(ctx, group_name))

    asg.set_desired_capacity(AutoScalingGroupName=group_name, DesiredCapacity=1, HonorCooldown=False)

    # Terminating a Pending instance can fold into the in-flight launch activity instead of
    # recording its own, so wait for InService first.
    def _instances_probe():
        return asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
            "AutoScalingGroups"
        ][0]["Instances"]

    instances = _poll_until(
        _instances_probe,
        lambda ins: len(ins) == 1 and ins[0].get("LifecycleState") == "InService",
        timeout_s=300,
        interval_s=5,
    )
    instance_id = instances[0]["InstanceId"]

    # Terminate is transiently refused while the launch activity is still settling.
    def _terminate_with_retry():
        deadline = time.monotonic() + 90
        while True:
            try:
                asg.terminate_instance_in_auto_scaling_group(
                    InstanceId=instance_id, ShouldDecrementDesiredCapacity=True
                )
                return
            except ClientError as err:
                code = err.response["Error"]["Code"]
                if code in ("ScalingActivityInProgress", "ResourceContention") and time.monotonic() < deadline:
                    time.sleep(5)
                    continue
                raise

    _terminate_with_retry()

    def _activities_probe():
        return asg.describe_scaling_activities(AutoScalingGroupName=group_name)["Activities"]

    activities = _poll_until(_activities_probe, lambda acts: len(acts) >= 2, timeout_s=90, interval_s=5)

    activity_ids = [a["ActivityId"] for a in activities]
    assert len(activity_ids) == len(set(activity_ids)), "duplicate ActivityIds in scaling activity log"
    for a in activities:
        assert a.get("ActivityId"), "activity missing server-assigned ActivityId"
        assert a.get("Cause"), "activity missing server-generated Cause"
        assert a.get("StatusCode") in {
            "PendingSpotBidPlacement",
            "WaitingForSpotInstanceRequestId",
            "WaitingForSpotInstanceId",
            "WaitingForInstanceId",
            "PreInService",
            "InProgress",
            "WaitingForELBConnectionDraining",
            "MidLifecycleAction",
            "WaitingForInstanceWarmup",
            "Successful",
            "Failed",
            "Cancelled",
        }, f"unexpected StatusCode: {a.get('StatusCode')}"
        assert a.get("StartTime"), "activity missing server-assigned StartTime"

    causes = " ".join(a["Cause"].lower() for a in activities)
    assert "desired capacity" in causes or "increasing" in causes, (
        f"no activity recorded the SetDesiredCapacity-triggered launch; causes: {causes!r}"
    )

    # The terminate activity is recorded asynchronously. Its Cause reads "... was taken out of
    # service in response to a user request, shrinking the capacity from 1 to 0." (no "terminat").
    def _causes_probe():
        acts = _activities_probe()
        return " ".join(a["Cause"].lower() for a in acts)

    causes = _poll_until(
        _causes_probe,
        lambda c: "taken out of service" in c or "shrinking the capacity" in c,
        timeout_s=120,
        interval_s=5,
    )
    assert "taken out of service" in causes or "shrinking the capacity" in causes, (
        f"no activity recorded the TerminateInstanceInAutoScalingGroup call; causes: {causes!r}"
    )


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _get_default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return subnets[0]["SubnetId"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _delete_asg_force(ctx, name: str) -> None:
    asg = ctx.client("autoscaling")
    for _ in range(30):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
