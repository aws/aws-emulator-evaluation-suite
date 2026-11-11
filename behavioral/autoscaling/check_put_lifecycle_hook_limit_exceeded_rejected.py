"""put-lifecycle-hook-limit-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-lifecycle-hook-limit-exceeded-rejected"
GROUP = "state-machine"
SERVICES = ["autoscaling"]

_HOOK_LIMIT = 50


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutLifecycleHook is rejected with LimitExceeded once an Auto Scaling group already has
    the maximum of 50 lifecycle hooks, the hook count stays at the limit (the rejected hook is
    not added), and freeing one slot lets a new hook succeed (positive control)."""
    autoscaling = ctx.client("autoscaling")
    subnet_ids = _default_subnet_ids(ctx, count=1)
    group = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=group,
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=",".join(subnet_ids),
        LaunchTemplate={"LaunchTemplateId": _create_launch_template(ctx)},
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=group, ForceDelete=True)
    )

    hook_names = [ctx.unique_name(f"sim2real-hook-{i}-") for i in range(_HOOK_LIMIT)]
    for hook_name in hook_names:
        autoscaling.put_lifecycle_hook(
            LifecycleHookName=hook_name,
            AutoScalingGroupName=group,
            LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        )

    existing = autoscaling.describe_lifecycle_hooks(AutoScalingGroupName=group)["LifecycleHooks"]
    assert len(existing) == _HOOK_LIMIT, f"expected {_HOOK_LIMIT} hooks, got {len(existing)}"

    overflow_name = ctx.unique_name("sim2real-hook-overflow-")
    code, message = _error(
        lambda: autoscaling.put_lifecycle_hook(
            LifecycleHookName=overflow_name,
            AutoScalingGroupName=group,
            LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        )
    )
    assert code == "LimitExceeded", f"expected LimitExceeded past the per-group hook cap, got {code}"
    expected_message = "You cannot have more than 50 hooks per Auto Scaling group"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_reject = autoscaling.describe_lifecycle_hooks(AutoScalingGroupName=group)["LifecycleHooks"]
    assert len(after_reject) == _HOOK_LIMIT, (
        f"hook count must stay at {_HOOK_LIMIT} after the rejected PutLifecycleHook, got {len(after_reject)}"
    )
    assert overflow_name not in {h["LifecycleHookName"] for h in after_reject}, (
        "the rejected hook must not have been added"
    )

    # Positive control: freeing one slot lets a new hook succeed.
    autoscaling.delete_lifecycle_hook(LifecycleHookName=hook_names[0], AutoScalingGroupName=group)
    autoscaling.put_lifecycle_hook(
        LifecycleHookName=overflow_name,
        AutoScalingGroupName=group,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
    )
    final = autoscaling.describe_lifecycle_hooks(AutoScalingGroupName=group)["LifecycleHooks"]
    assert len(final) == _HOOK_LIMIT, f"expected {_HOOK_LIMIT} hooks after freeing a slot, got {len(final)}"
    final_names = {h["LifecycleHookName"] for h in final}
    assert overflow_name in final_names, (
        f"expected {overflow_name} to succeed once a slot was freed, got hooks {sorted(final_names)}"
    )


import time
from botocore.exceptions import ClientError


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _default_subnet_ids(ctx, count: int = 1) -> list[str]:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:

        raise AssertionError("no shared network VPC subnets available in this account/region")
    return [s["SubnetId"] for s in subnets[:count]]


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _create_launch_template(ctx, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)
    name = ctx.unique_name("sim2real-behav-lt-")
    resp = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
