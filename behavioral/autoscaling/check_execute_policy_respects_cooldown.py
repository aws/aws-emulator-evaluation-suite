"""execute-policy-respects-cooldown."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-policy-respects-cooldown"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second ExecutePolicy(HonorCooldown=True) inside the SimpleScaling cooldown is skipped:
    a later HonorCooldown=False call lands DesiredCapacity on 2, not the 3 a re-applied
    adjustment would give."""
    asg = ctx.client("autoscaling")
    lt_name = _create_launch_template(ctx, ami_id=_get_al2_ami(ctx))
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=0,
        MaxSize=5,
        DesiredCapacity=0,
        VPCZoneIdentifier=_subnet_id(ctx),
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: _delete_asg_force(ctx, group_name))

    policy_name = ctx.unique_name("sim2real-behav-policy-")
    asg.put_scaling_policy(
        AutoScalingGroupName=group_name,
        PolicyName=policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
        Cooldown=300,
    )
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: asg.delete_policy(AutoScalingGroupName=group_name, PolicyName=policy_name)
        )
    )

    def _desired_probe():
        return asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
            "AutoScalingGroups"
        ][0]["DesiredCapacity"]

    asg.execute_policy(AutoScalingGroupName=group_name, PolicyName=policy_name, HonorCooldown=True)
    after_first = _poll_until(ctx, _desired_probe, lambda d: d == 1, timeout_s=60, interval_s=2)
    assert after_first == 1, f"first ExecutePolicy call did not apply the adjustment: {after_first}"

    # fired immediately, well inside the 300s cooldown window started by the first call --
    # a target may either silently decline to re-apply the adjustment or raise
    # ScalingActivityInProgress; either is cooldown being honored, anything else is not.
    try:
        asg.execute_policy(AutoScalingGroupName=group_name, PolicyName=policy_name, HonorCooldown=True)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ScalingActivityInProgress", (
            f"second ExecutePolicy(HonorCooldown=True) call inside the cooldown window raised "
            f"an unexpected error instead of silently honoring cooldown: {code}"
        )

    before_override = _desired_probe()
    assert before_override == 1, (
        f"the HonorCooldown=True call inside the cooldown window changed DesiredCapacity to "
        f"{before_override}"
    )

    # Contrast: a cooldown-overriding call, ordered after the honoring call and after the first
    # launch finishes (an in-progress activity blocks any execution), lands the group on 2
    # unless the honoring call re-applied the adjustment too.
    _poll_until(ctx, lambda: [
        i["LifecycleState"] for g in asg.describe_auto_scaling_groups(
            AutoScalingGroupNames=[group_name])["AutoScalingGroups"] for i in g.get("Instances", [])
    ], lambda states: states == ["InService"], timeout_s=420, interval_s=2)
    _poll_until(ctx, lambda: [
        a["StatusCode"] for a in asg.describe_scaling_activities(
            AutoScalingGroupName=group_name)["Activities"]
    ], lambda codes: all(c in ("Successful", "Failed", "Cancelled") for c in codes), timeout_s=300, interval_s=2)
    left = ctx.time_left()
    deadline = time.monotonic() + (300 if left is None else min(300, left))
    while True:
        try:
            asg.execute_policy(AutoScalingGroupName=group_name, PolicyName=policy_name, HonorCooldown=False)
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "ScalingActivityInProgress" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    after_override = _poll_until(ctx, _desired_probe, lambda d: d != 1, timeout_s=90, interval_s=2)
    assert after_override == 2, (
        f"expected DesiredCapacity 2 after the HonorCooldown=False call, got {after_override}: "
        f"the HonorCooldown=True call inside the cooldown window was not skipped"
    )


def _poll_until(ctx, probe, predicate, timeout_s=300.0, interval_s=2.0):
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


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
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _subnet_id(ctx) -> str:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    return sorted(subnets, key=lambda s: s["AvailabilityZone"])[0]["SubnetId"]


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

