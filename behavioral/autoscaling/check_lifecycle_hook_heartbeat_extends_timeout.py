"""lifecycle-hook-heartbeat-extends-timeout."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "lifecycle-hook-heartbeat-extends-timeout"
GROUP = "visibility-timeout-ttl"
SERVICES = ["autoscaling"]

#: The documented minimum HeartbeatTimeout (PutLifecycleHook: 30 to 7200 seconds).
HEARTBEAT_TIMEOUT_S = 30
ABANDONED_STATES = {"Terminating:Wait", "Terminating:Proceed", "Terminating", "Terminated"}


# timing:real-time — workflow: 30 s https://docs.aws.amazon.com/autoscaling/ec2/userguide/lifecycle-hooks.html
@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """RecordLifecycleActionHeartbeat extends a lifecycle hook's pending window and
    CompleteLifecycleAction resolves it before expiry; a sibling instance never heartbeated is
    abandoned at about the original deadline, proving the timeout is enforced."""
    asg = ctx.client("autoscaling")

    subnet_id = _get_default_subnet(ctx)
    lt_name = _create_launch_template(ctx)
    group_name = _create_asg_with_template(
        ctx, lt_name, subnet_id, min_size=2, max_size=2, desired=2, DefaultInstanceWarmup=0
    )

    hook_name = ctx.unique_name("sim2real-hook-")
    asg.put_lifecycle_hook(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=group_name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        HeartbeatTimeout=HEARTBEAT_TIMEOUT_S,
        DefaultResult="ABANDON",
    )

    heartbeated_id, control_id = _wait_for_two_instances_lifecycle_state(
        ctx, group_name, "Pending:Wait", timeout_s=180.0
    )
    entered_wait_at = time.monotonic()

    # Heartbeat only ONE of the two instances partway through the window (well before the
    # HeartbeatTimeout elapses), leaving the other un-heartbeated as the control. Poll (rather
    # than blindly sleep) up to that point, asserting on every iteration that neither instance
    # has already been abandoned early.
    _poll_while_lifecycle_states_hold(
        ctx,
        group_name,
        {heartbeated_id: "Pending:Wait", control_id: "Pending:Wait"},
        until_monotonic=entered_wait_at + HEARTBEAT_TIMEOUT_S * 0.6,
    )
    asg.record_lifecycle_action_heartbeat(
        LifecycleHookName=hook_name, AutoScalingGroupName=group_name, InstanceId=heartbeated_id
    )

    # Past the ORIGINAL deadline: the heartbeated instance must still be waiting, and the
    # un-heartbeated control must have been abandoned by ~the original deadline. The control
    # leg is what makes "still Pending:Wait" meaningful -- it proves ABANDON actually fires on
    # this target near the declared deadline, so the heartbeated instance surviving past that
    # same deadline is evidence of an extension, not evidence that timeouts are never enforced.
    heartbeated_state, control_state, control_abandoned = _poll_for_extension_and_control_abandon(
        ctx,
        group_name,
        heartbeated_id,
        control_id,
        hold_until_monotonic=entered_wait_at + HEARTBEAT_TIMEOUT_S + 5,
        abandon_deadline_monotonic=entered_wait_at + HEARTBEAT_TIMEOUT_S + 60,
    )
    assert heartbeated_state == "Pending:Wait", (
        f"instance left Pending:Wait ({heartbeated_state}) before the heartbeat-extended "
        "timeout could have elapsed -- heartbeat did not extend the hook's window"
    )
    assert control_abandoned, (
        f"un-heartbeated control instance {control_id} was never abandoned (last state "
        f"{control_state!r}) -- this target may not enforce HeartbeatTimeout/DefaultResult=ABANDON "
        "at all, which would make the heartbeated instance's Pending:Wait meaningless as proof of "
        "an extension"
    )

    # Stop the control's abandon-and-relaunch churn (ABANDON releases capacity back to the ASG)
    # before resolving the heartbeated instance.
    asg.update_auto_scaling_group(
        AutoScalingGroupName=group_name, MinSize=1, MaxSize=1, DesiredCapacity=1
    )

    asg.complete_lifecycle_action(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=group_name,
        LifecycleActionResult="CONTINUE",
        InstanceId=heartbeated_id,
    )

    resolved_instance_id = _wait_for_instance_lifecycle_state(ctx, group_name, "InService", timeout_s=180.0)
    assert resolved_instance_id == heartbeated_id, (
        f"expected the SAME instance ({heartbeated_id}) to resolve to InService, got {resolved_instance_id}"
    )


def _get_launch_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
    return resp["Parameter"]["Value"]


def _get_default_subnet(ctx) -> str:

    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError("no shared network VPC subnet available in this account/region")
    return subnets[0]["SubnetId"]


def _create_launch_template(ctx) -> str:
    ec2 = ctx.client("ec2")
    ami = _get_launch_ami(ctx)
    name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _create_asg_with_template(
    ctx, lt_name: str, subnet_id: str, min_size: int, max_size: int, desired: int, **extra: Any
) -> str:
    asg = ctx.client("autoscaling")
    name = ctx.unique_name("sim2real-asg-")
    params = dict(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        HealthCheckGracePeriod=0,
    )
    params.update(extra)
    asg.create_auto_scaling_group(**params)
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True))
    return name


def _group_instances(ctx, group_name: str) -> list[dict[str, Any]]:
    asg = ctx.client("autoscaling")
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
    return groups[0]["Instances"] if groups else []


def _current_instance_lifecycle_state(ctx, group_name: str, instance_id: str) -> str | None:
    for inst in _group_instances(ctx, group_name):
        if inst["InstanceId"] == instance_id:
            return inst["LifecycleState"]
    return None


def _wait_for_two_instances_lifecycle_state(
    ctx, group_name: str, state: str, timeout_s: float, interval_s: float = 5.0
) -> tuple[str, str]:
    deadline = time.monotonic() + timeout_s
    last_seen: list[str] = []
    while time.monotonic() < deadline:
        matching = [
            inst["InstanceId"] for inst in _group_instances(ctx, group_name) if inst["LifecycleState"] == state
        ]
        last_seen = matching
        if len(matching) >= 2:
            return matching[0], matching[1]
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out waiting for two instances to reach {state!r} (last seen matching: {last_seen!r})"
    )


def _poll_while_lifecycle_states_hold(
    ctx,
    group_name: str,
    expected_by_instance: dict[str, str],
    until_monotonic: float,
    interval_s: float = 5.0,
) -> None:
    """Assert on every poll that each instance in `expected_by_instance` stays at its expected
    state until `until_monotonic`, so an early departure is caught immediately."""
    while True:
        now = time.monotonic()
        if now >= until_monotonic:
            return
        for instance_id, expected_state in expected_by_instance.items():
            state = _current_instance_lifecycle_state(ctx, group_name, instance_id)
            assert state == expected_state, (
                f"instance {instance_id} left {expected_state!r} unexpectedly (now {state!r}) while waiting"
            )
        time.sleep(min(interval_s, until_monotonic - now))


def _poll_for_extension_and_control_abandon(
    ctx,
    group_name: str,
    heartbeated_id: str,
    control_id: str,
    hold_until_monotonic: float,
    abandon_deadline_monotonic: float,
    interval_s: float = 5.0,
) -> tuple[str | None, str | None, bool]:
    """Poll both instances, asserting the heartbeated one never leaves Pending:Wait early; return
    once the control is abandoned at/after `hold_until_monotonic` or the abandon deadline passes."""
    heartbeated_state: str | None = "Pending:Wait"
    control_state: str | None = "Pending:Wait"
    control_abandoned = False
    deadline = max(hold_until_monotonic, abandon_deadline_monotonic)
    while True:
        now = time.monotonic()
        heartbeated_state = _current_instance_lifecycle_state(ctx, group_name, heartbeated_id)
        assert heartbeated_state == "Pending:Wait", (
            f"heartbeated instance {heartbeated_id} left Pending:Wait unexpectedly (now "
            f"{heartbeated_state!r}) while waiting"
        )
        control_state = _current_instance_lifecycle_state(ctx, group_name, control_id)
        if control_state is None or control_state in ABANDONED_STATES:
            control_abandoned = True
        if now >= deadline or (control_abandoned and now >= hold_until_monotonic):
            return heartbeated_state, control_state, control_abandoned
        time.sleep(min(interval_s, deadline - now))


def _wait_for_instance_lifecycle_state(ctx, group_name: str, state: str, timeout_s: float, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_seen = None
    while time.monotonic() < deadline:
        instances = _group_instances(ctx, group_name)
        for inst in instances:
            last_seen = inst["LifecycleState"]
            if inst["LifecycleState"] == state:
                return inst["InstanceId"]
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for an instance to reach {state!r} (last seen: {last_seen!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
