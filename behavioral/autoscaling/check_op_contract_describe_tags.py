"""op-contract-describeTags."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeTags"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTags with a Filter returns the exact tag set created via
    CreateOrUpdateTags; an invalid pagination token is rejected with ValidationError."""
    asg = ctx.client("autoscaling")
    group_name = _create_empty_asg(ctx)

    asg.create_or_update_tags(
        Tags=[
            {
                "ResourceId": group_name,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real-env",
                "Value": "test",
                "PropagateAtLaunch": True,
            }
        ]
    )
    ctx.on_cleanup(
        lambda: asg.delete_tags(
            Tags=[
                {
                    "ResourceId": group_name,
                    "ResourceType": "auto-scaling-group",
                    "Key": "sim2real-env",
                    "Value": "test",
                }
            ]
        )
    )

    tags = asg.describe_tags(
        Filters=[{"Name": "auto-scaling-group", "Values": [group_name]}]
    )["Tags"]
    assert len(tags) == 1, f"expected exactly 1 tag for {group_name}, got {len(tags)}: {tags}"
    tag = tags[0]
    assert tag["Key"] == "sim2real-env", f"expected Key='sim2real-env', got {tag['Key']!r}"
    assert tag["Value"] == "test", f"expected Value='test', got {tag['Value']!r}"
    assert tag["ResourceType"] == "auto-scaling-group", (
        f"expected ResourceType='auto-scaling-group', got {tag['ResourceType']!r}"
    )
    assert tag["ResourceId"] == group_name, (
        f"expected ResourceId={group_name!r}, got {tag['ResourceId']!r}"
    )
    assert tag["PropagateAtLaunch"] is True, (
        f"expected PropagateAtLaunch=True, got {tag['PropagateAtLaunch']!r}"
    )

    code, message = _error(
        lambda: asg.describe_tags(NextToken="sim2real-not-a-real-token")
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = "NextToken: sim2real-not-a-real-token"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target accepting what real AWS refuses must not read as a code mismatch."""
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
