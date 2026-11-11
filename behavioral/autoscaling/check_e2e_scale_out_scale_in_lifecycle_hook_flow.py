"""e2e-scale-out-scale-in-lifecycle-hook-flow."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-scale-out-scale-in-lifecycle-hook-flow"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A launch hook holds a scaled-out instance in Pending:Wait until completed, then InService
    matches desired capacity with the instance running at EC2; scale-in empties the group and
    the deleted group is unusable."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    subnet_id = _default_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)

    lt_name = ctx.unique_name("sim2real-lt-hook-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id),
                                        "InvalidLaunchTemplateId.NotFound"))

    asg_name = ctx.unique_name("sim2real-asg-hook-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: autoscaling.delete_auto_scaling_group(
        AutoScalingGroupName=asg_name, ForceDelete=True
    )))

    hook_name = ctx.unique_name("sim2real-hook-")
    autoscaling.put_lifecycle_hook(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=asg_name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        DefaultResult="ABANDON",
        HeartbeatTimeout=300,
    )

    def _instances() -> list[dict[str, Any]]:
        return autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ][0]["Instances"]

    # Scale out: the new instance must be held in Pending:Wait by the launch hook.
    autoscaling.set_desired_capacity(
        AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False
    )
    held = _poll_until(
        _instances,
        lambda insts: any(i["LifecycleState"] == "Pending:Wait" for i in insts),
        timeout_s=240,
        interval_s=10,
    )
    instance_id = next(i["InstanceId"] for i in held if i["LifecycleState"] == "Pending:Wait")

    autoscaling.record_lifecycle_action_heartbeat(
        LifecycleHookName=hook_name, AutoScalingGroupName=asg_name, InstanceId=instance_id
    )
    autoscaling.complete_lifecycle_action(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=asg_name,
        InstanceId=instance_id,
        LifecycleActionResult="CONTINUE",
    )

    in_service = _poll_until(
        _instances,
        lambda insts: len(insts) == 1 and insts[0]["LifecycleState"] == "InService",
        timeout_s=240,
        interval_s=10,
    )
    assert len(in_service) == 1, f"expected exactly 1 instance InService, observed {in_service!r}"
    assert in_service[0]["LifecycleState"] == "InService", (
        f"expected the released instance's LifecycleState to be InService, "
        f"got {in_service[0]['LifecycleState']!r}"
    )
    # The autoscaling-side state transition must be backed by a real EC2 consequence, not
    # just a label change on the group's own Instances collection.
    ec2_state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert ec2_state["State"]["Name"] == "running", (
        f"expected EC2 instance {instance_id} to be running once CompleteLifecycleAction "
        f"released it to InService, got {ec2_state['State']['Name']!r}"
    )
    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group["DesiredCapacity"] == 1 == len(in_service), (
        f"expected DesiredCapacity == 1 == observed instance count, "
        f"got DesiredCapacity={group['DesiredCapacity']!r} instances={len(in_service)}"
    )

    # Scale back in to zero and confirm the capacity consequence.
    autoscaling.set_desired_capacity(
        AutoScalingGroupName=asg_name, DesiredCapacity=0, HonorCooldown=False
    )
    empty = _poll_until(_instances, lambda insts: len(insts) == 0, timeout_s=240, interval_s=10)
    assert empty == [], f"expected zero instances after scaling in to 0, observed {empty!r}"

    autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name)

    def _group_gone() -> bool:
        resp = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        return len(resp["AutoScalingGroups"]) == 0

    _poll_until(_group_gone, lambda gone: gone, timeout_s=180, interval_s=10)

    # The deleted group must be unusable, not merely absent from a describe -- an operation
    # that demonstrably worked earlier (SetDesiredCapacity) must now be rejected by name.
    try:
        autoscaling.set_desired_capacity(
            AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False
        )
    except ClientError as exc:
        dead_error = exc.response.get("Error", {})
    else:
        raise AssertionError(f"SetDesiredCapacity on the deleted group {asg_name} unexpectedly succeeded")
    dead_code = dead_error.get("Code")
    assert dead_code == "ValidationError", (
        f"expected SetDesiredCapacity on the deleted group {asg_name} to be rejected with "
        f"ValidationError, got {dead_code!r}"
    )
    assert dead_error.get("Message") == "AutoScalingGroup name not found - null", (
        f"expected message 'AutoScalingGroup name not found - null', got {dead_error.get('Message')!r}"
    )


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if not subnets:
        raise AssertionError(
            "no shared-network subnet found in this account/region to launch ASG instances into"
        )
    return subnets[0]["SubnetId"]


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]


def _unless_gone(fn, *not_found):
    """Run one cleanup call; only a not-found answer means the resource is already gone."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] in not_found or (
                err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
            return
        raise


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 180.0,
    interval_s: float = 10.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
