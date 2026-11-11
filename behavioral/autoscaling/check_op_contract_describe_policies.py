"""op-contract-describePolicies."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describePolicies"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribePolicies round-trips the fields set by PutScalingPolicy; an invalid
    pagination token is rejected with InvalidNextToken."""
    asg = ctx.client("autoscaling")
    group_name = _create_empty_asg(ctx)

    policy_name = ctx.unique_name("sim2real-behav-policy-")
    put_resp = asg.put_scaling_policy(
        AutoScalingGroupName=group_name,
        PolicyName=policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
        Cooldown=60,
    )
    policy_arn = put_resp["PolicyARN"]
    ctx.on_cleanup(
        lambda: asg.delete_policy(AutoScalingGroupName=group_name, PolicyName=policy_name)
    )

    described = asg.describe_policies(
        AutoScalingGroupName=group_name, PolicyNames=[policy_name]
    )["ScalingPolicies"]
    assert len(described) == 1, f"expected exactly 1 policy, got {len(described)}"
    policy = described[0]
    assert policy["PolicyARN"] == policy_arn, (
        f"expected PolicyARN {policy_arn!r}, got {policy['PolicyARN']!r}"
    )
    assert policy["PolicyType"] == "SimpleScaling", (
        f"expected PolicyType 'SimpleScaling', got {policy['PolicyType']!r}"
    )
    assert policy["AdjustmentType"] == "ChangeInCapacity", (
        f"expected AdjustmentType 'ChangeInCapacity', got {policy['AdjustmentType']!r}"
    )
    assert policy["ScalingAdjustment"] == 1, (
        f"expected ScalingAdjustment 1, got {policy['ScalingAdjustment']!r}"
    )
    assert policy["Cooldown"] == 60, f"expected Cooldown 60, got {policy['Cooldown']!r}"

    code, message = _error(
        lambda: asg.describe_policies(
            AutoScalingGroupName=group_name, NextToken="sim2real-not-a-real-token"
        )
    )
    assert code == "InvalidNextToken", f"expected InvalidNextToken, got {code}"
    expected_message = "The pagination token 'sim2real-not-a-real-token' is invalid"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore error code. An unexpected success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


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
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_empty_asg(ctx):
    asg = ctx.client("autoscaling")
    ami_id = _latest_al2023_ami(ctx)
    subnet_id, _vpc_id = _default_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
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
