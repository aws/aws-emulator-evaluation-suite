"""e2e-scale-out-lifecycle-hook-terminate-flow."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-scale-out-lifecycle-hook-terminate-flow"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Launch and terminate hooks hold an instance in Pending:Wait and Terminating:Wait until
    CompleteLifecycleAction; after scale-in the group reports DesiredCapacity 0 and no instances."""
    ec2 = ctx.client("ec2")
    asgc = ctx.client("autoscaling")

    ami_id = _latest_al2_ami(ctx)
    az = _first_az(ctx)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-behav", "Value": lt_name}]}
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    asgc.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        Tags=[{"Key": "sim2real-behav", "Value": asg_name, "PropagateAtLaunch": False}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(lambda: _delete_asg_and_wait(ctx, asg_name))

    launch_hook = ctx.unique_name("sim2real-behav-launch-hook-")
    term_hook = ctx.unique_name("sim2real-behav-term-hook-")
    asgc.put_lifecycle_hook(
        LifecycleHookName=launch_hook,
        AutoScalingGroupName=asg_name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        HeartbeatTimeout=600,
        DefaultResult="ABANDON",
    )
    asgc.put_lifecycle_hook(
        LifecycleHookName=term_hook,
        AutoScalingGroupName=asg_name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_TERMINATING",
        HeartbeatTimeout=600,
        DefaultResult="ABANDON",
    )

    asgc.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False)

    instance_id, state = _poll_instance_state(ctx, asg_name, {"Pending:Wait"}, timeout_s=240)
    assert state == "Pending:Wait", f"instance never reached Pending:Wait (last seen {state})"

    asgc.complete_lifecycle_action(
        LifecycleHookName=launch_hook,
        AutoScalingGroupName=asg_name,
        LifecycleActionResult="CONTINUE",
        InstanceId=instance_id,
    )

    _, state = _poll_instance_state(ctx, asg_name, {"InService"}, timeout_s=240, instance_id=instance_id)
    assert state == "InService", f"instance never reached InService after CompleteLifecycleAction (last seen {state})"

    asgc.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=0, HonorCooldown=False)

    _, state = _poll_instance_state(ctx, asg_name, {"Terminating:Wait"}, timeout_s=240, instance_id=instance_id)
    assert state == "Terminating:Wait", f"instance never reached Terminating:Wait (last seen {state})"

    asgc.complete_lifecycle_action(
        LifecycleHookName=term_hook,
        AutoScalingGroupName=asg_name,
        LifecycleActionResult="CONTINUE",
        InstanceId=instance_id,
    )

    deadline = time.monotonic() + 240
    remaining = None
    while time.monotonic() < deadline:
        group = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
        remaining = group.get("Instances", [])
        if not remaining:
            break
        time.sleep(5)
    assert remaining == [], f"instance never fully terminated, still present: {remaining}"

    activities = asgc.describe_scaling_activities(AutoScalingGroupName=asg_name)["Activities"]
    own_activities = [
        a for a in activities if instance_id in a.get("Description", "") or instance_id in a.get("Cause", "")
    ]
    assert len(own_activities) >= 2, (
        f"expected at least 2 recorded scaling activities referencing {instance_id} "
        f"(one for the launch, one for the terminate), got {len(own_activities)}: {activities}"
    )


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"][
        "Value"
    ]


def _first_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
        "AvailabilityZones"
    ]
    return zones[0]["ZoneName"]


def _poll_instance_state(ctx, asg_name: str, wanted_states: set, timeout_s: float, instance_id: str | None = None):
    asgc = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        group = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
        instances = group.get("Instances", [])
        if instance_id is not None:
            instances = [i for i in instances if i["InstanceId"] == instance_id]
        if instances:
            last_state = instances[0]["LifecycleState"]
            if last_state in wanted_states:
                return instances[0]["InstanceId"], last_state
        time.sleep(5)
    return instance_id, last_state


def _delete_asg_and_wait(ctx, asg_name: str, timeout_s: float = 300.0) -> None:
    asgc = ctx.client("autoscaling")
    try:
        asgc.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        if not groups:
            return
        time.sleep(2)
    raise RuntimeError(f"group {asg_name} still listed {timeout_s}s after its ForceDelete")


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
