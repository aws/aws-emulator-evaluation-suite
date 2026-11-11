"""op-contract-deletePolicy."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deletePolicy"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePolicy removes a scaling policy (DescribePolicies no longer returns
    it); calling DeletePolicy again on the now-deleted name is rejected with
    ValidationError since the policy no longer exists."""
    asg = ctx.client("autoscaling")
    group_name = _create_empty_asg(ctx)

    policy_name = ctx.unique_name("sim2real-behav-policy-")
    asg.put_scaling_policy(
        AutoScalingGroupName=group_name,
        PolicyName=policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
        Cooldown=60,
    )
    present = asg.describe_policies(
        AutoScalingGroupName=group_name, PolicyNames=[policy_name]
    )["ScalingPolicies"]
    assert len(present) == 1, f"expected exactly 1 policy named {policy_name!r}, got {present!r}"

    delete_resp = asg.delete_policy(AutoScalingGroupName=group_name, PolicyName=policy_name)
    status = delete_resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 from DeletePolicy, got {status}"

    gone = asg.describe_policies(AutoScalingGroupName=group_name, PolicyNames=[policy_name])[
        "ScalingPolicies"
    ]
    assert gone == [], f"expected no policies named {policy_name!r} after delete, got {gone!r}"

    # --- boundary: deleting an already-deleted policy is rejected, since the
    # policy name no longer resolves to a policy ---
    code, message = _error(
        lambda: asg.delete_policy(AutoScalingGroupName=group_name, PolicyName=policy_name)
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = f"Policy {policy_name} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    still_gone = asg.describe_policies(AutoScalingGroupName=group_name, PolicyNames=[policy_name])[
        "ScalingPolicies"
    ]
    assert still_gone == [], (
        f"expected no policies named {policy_name!r} after the rejected re-delete, got {still_gone!r}"
    )


# ===== helpers =====
def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _latest_al2023_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _delete_with_retry(fn, *, not_found_code: str, timeout_s: float, interval_s: float = 3.0) -> None:
    """Retry a delete that fails with DependencyViolation while an ASG instance this check just
    force-deleted is still detaching its ENI in the background -- the ASG delete call returns long
    before that termination completes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code == not_found_code:
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


def _own_subnet(ctx) -> str:
    """Subnet in a VPC this check creates and owns, rather than assuming the account already has
    a default VPC -- a freshly provisioned account may not."""
    ec2 = ctx.client("ec2")
    cidr = "10.203.0.0/24"
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _delete_with_retry(
            lambda: ec2.delete_vpc(VpcId=vpc_id), not_found_code="InvalidVpcID.NotFound", timeout_s=30.0
        )
    )
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
        interval_s=3.0,
    )
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_with_retry(
            lambda: ec2.delete_subnet(SubnetId=subnet_id),
            not_found_code="InvalidSubnetID.NotFound",
            timeout_s=20.0,
        )
    )
    return subnet_id


def _create_launch_template(ctx, ami_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_empty_asg(ctx):
    asg = ctx.client("autoscaling")
    ami_id = _latest_al2023_ami(ctx)
    subnet_id = _own_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=2,
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
