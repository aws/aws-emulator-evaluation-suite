"""op-contract-executePolicy."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-executePolicy"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExecutePolicy triggers a real scaling Activity that moves DesiredCapacity by
    the policy's ScalingAdjustment; executing a nonexistent policy name is rejected
    with ValidationError and leaves DesiredCapacity unchanged."""
    asg = ctx.client("autoscaling")
    group_name = _create_empty_asg(ctx, max_size=3)

    policy_name = ctx.unique_name("sim2real-behav-policy-")
    asg.put_scaling_policy(
        AutoScalingGroupName=group_name,
        PolicyName=policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
        Cooldown=1,
    )

    before = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
        "AutoScalingGroups"
    ][0]["DesiredCapacity"]
    assert before == 0, f"expected freshly created ASG to start at DesiredCapacity 0, got {before}"

    asg.execute_policy(AutoScalingGroupName=group_name, PolicyName=policy_name)

    def _probe():
        return asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
            "AutoScalingGroups"
        ][0]["DesiredCapacity"]

    after = _poll_until(_probe, lambda cap: cap == before + 1, timeout_s=60.0, interval_s=3.0)
    assert after == 1, f"expected ExecutePolicy to move DesiredCapacity to {before + 1}, got {after}"

    def _activities_probe():
        return asg.describe_scaling_activities(AutoScalingGroupName=group_name)["Activities"]

    activities = _poll_until(
        _activities_probe, lambda acts: len(acts) >= 1, timeout_s=60.0, interval_s=3.0
    )
    assert len(activities) >= 1, "expected ExecutePolicy to record at least one scaling activity"
    assert any(policy_name in (a.get("Cause") or "") for a in activities), (
        "expected a scaling activity caused by the executed policy"
    )

    # --- error boundary: nonexistent PolicyName ---
    bogus_policy = ctx.unique_name("sim2real-behav-nopolicy-")
    code, message = _error(
        lambda: asg.execute_policy(AutoScalingGroupName=group_name, PolicyName=bogus_policy)
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = f"Policy {bogus_policy} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unchanged = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
        "AutoScalingGroups"
    ][0]["DesiredCapacity"]
    assert unchanged == 1, "DesiredCapacity must not change from a rejected ExecutePolicy call"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _latest_al2023_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]

    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in shared network")
    return subnets[0]["SubnetId"], vpc_id


def _create_launch_template(ctx, ami_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_empty_asg(ctx, max_size=2):
    asg = ctx.client("autoscaling")
    ami_id = _latest_al2023_ami(ctx)
    subnet_id, _vpc_id = _default_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=max_size,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )

    def _delete_group():
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True)
        except ClientError as err:
            error = err.response["Error"]
            if error["Code"] != "ValidationError" or "not found" not in error.get("Message", ""):
                raise

    ctx.on_cleanup(_delete_group)
    return group_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
