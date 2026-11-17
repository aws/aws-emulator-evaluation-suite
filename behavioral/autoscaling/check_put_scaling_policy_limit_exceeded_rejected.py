"""put-scaling-policy-limit-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-scaling-policy-limit-exceeded-rejected"
GROUP = "state-machine"
SERVICES = ["autoscaling"]

_POLICY_LIMIT = 50


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutScalingPolicy is rejected with LimitExceeded once an Auto Scaling group already has
    the maximum of 50 scaling policies, the policy count stays at the limit (the rejected policy
    is not added), and freeing one slot lets a new policy succeed (positive control)."""
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

    policy_names = [ctx.unique_name(f"sim2real-pol-{i}-") for i in range(_POLICY_LIMIT)]
    for policy_name in policy_names:
        autoscaling.put_scaling_policy(
            PolicyName=policy_name,
            AutoScalingGroupName=group,
            PolicyType="SimpleScaling",
            AdjustmentType="ChangeInCapacity",
            ScalingAdjustment=1,
            Cooldown=300,
        )

    existing = _list_policy_names(ctx, group)
    assert existing == set(policy_names), (
        f"expected the {_POLICY_LIMIT} created policies, got {sorted(existing)}"
    )

    overflow_name = ctx.unique_name("sim2real-pol-overflow-")
    code, message = _error(
        lambda: autoscaling.put_scaling_policy(
            PolicyName=overflow_name,
            AutoScalingGroupName=group,
            PolicyType="SimpleScaling",
            AdjustmentType="ChangeInCapacity",
            ScalingAdjustment=1,
            Cooldown=300,
        )
    )
    assert code == "LimitExceeded", f"expected LimitExceeded past the per-group policy cap, got {code}"
    expected_message = "The maximum limit of 50 policies has been reached."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_reject = _list_policy_names(ctx, group)
    assert after_reject == set(policy_names), (
        f"policy set must stay at the {_POLICY_LIMIT} created policies after the rejected "
        f"PutScalingPolicy, got {sorted(after_reject)}"
    )

    # Positive control: freeing one slot lets a new policy succeed.
    autoscaling.delete_policy(PolicyName=policy_names[0], AutoScalingGroupName=group)
    autoscaling.put_scaling_policy(
        PolicyName=overflow_name,
        AutoScalingGroupName=group,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
        Cooldown=300,
    )
    final = _list_policy_names(ctx, group)
    expected_final = set(policy_names[1:]) | {overflow_name}
    assert final == expected_final, (
        f"expected {overflow_name} to succeed once a slot was freed, got policies {sorted(final)}"
    )


from botocore.exceptions import ClientError


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_policy_names(ctx, group: str) -> set:
    autoscaling = ctx.client("autoscaling")
    paginator = autoscaling.get_paginator("describe_policies")
    return {
        p["PolicyName"]
        for page in paginator.paginate(AutoScalingGroupName=group)
        for p in page["ScalingPolicies"]
    }


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
