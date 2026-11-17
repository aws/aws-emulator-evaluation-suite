"""delete-lifecycle-hook-nonexistent-name."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-lifecycle-hook-nonexistent-name"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLifecycleHook for a hook name never created on the group fails, while deleting
    a hook that was actually created on that same group succeeds and removes it."""
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    ami_id = _latest_al2023_ami(ctx)
    subnet_id = _default_subnet(ctx)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
    )
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True))

    real_hook_name = ctx.unique_name("sim2real-behav-hook-")
    asg.put_lifecycle_hook(
        LifecycleHookName=real_hook_name,
        AutoScalingGroupName=group_name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
    )

    missing_hook_name = ctx.unique_name("sim2real-behav-hook-missing-")
    code, message = _error(
        lambda: asg.delete_lifecycle_hook(LifecycleHookName=missing_hook_name, AutoScalingGroupName=group_name)
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = f"No Lifecycle Hook found with name '{missing_hook_name}' for group '{group_name}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    hooks_after_reject = asg.describe_lifecycle_hooks(AutoScalingGroupName=group_name)["LifecycleHooks"]
    assert [h["LifecycleHookName"] for h in hooks_after_reject] == [real_hook_name], (
        f"a rejected DeleteLifecycleHook must not change the group's hooks, "
        f"expected only {real_hook_name!r}, got {[h['LifecycleHookName'] for h in hooks_after_reject]!r}"
    )

    asg.delete_lifecycle_hook(LifecycleHookName=real_hook_name, AutoScalingGroupName=group_name)
    hooks_after_delete = asg.describe_lifecycle_hooks(AutoScalingGroupName=group_name)["LifecycleHooks"]
    assert hooks_after_delete == [], f"expected no hooks after deleting {real_hook_name!r}, got {hooks_after_delete!r}"


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameter"]["Value"]


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in the shared network")
    return subnets[0]["SubnetId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
