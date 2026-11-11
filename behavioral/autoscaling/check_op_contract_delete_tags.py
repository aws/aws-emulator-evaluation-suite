"""op-contract-deleteTags."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteTags"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTags removes exactly the matching tag; deleting a tag key that was
    never set on the resource is idempotent and leaves the remaining tag set
    untouched."""
    asg = ctx.client("autoscaling")
    group_name = _create_empty_asg(ctx)

    asg.create_or_update_tags(
        Tags=[
            {
                "ResourceId": group_name,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real-env",
                "Value": "test",
                "PropagateAtLaunch": False,
            }
        ]
    )
    present = asg.describe_tags(
        Filters=[{"Name": "auto-scaling-group", "Values": [group_name]}]
    )["Tags"]
    assert len(present) == 1 and present[0]["Key"] == "sim2real-env", (
        f"expected exactly one tag sim2real-env after create, got {present}"
    )

    # --- boundary: deleting a key that was never set is idempotent, not an error ---
    delete_resp = asg.delete_tags(
        Tags=[
            {
                "ResourceId": group_name,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real-never-set",
                "Value": "whatever",
            }
        ]
    )
    status = delete_resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 deleting a never-set tag key, got {status}"
    unaffected = asg.describe_tags(
        Filters=[{"Name": "auto-scaling-group", "Values": [group_name]}]
    )["Tags"]
    assert len(unaffected) == 1 and unaffected[0]["Key"] == "sim2real-env", (
        f"deleting an unset tag key must leave the existing tag set untouched, got {unaffected}"
    )

    # --- success path: delete the real tag ---
    asg.delete_tags(
        Tags=[
            {
                "ResourceId": group_name,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real-env",
                "Value": "test",
            }
        ]
    )
    remaining = asg.describe_tags(
        Filters=[{"Name": "auto-scaling-group", "Values": [group_name]}]
    )["Tags"]
    assert remaining == [], f"expected no tags after deleting the last one, got {remaining}"


# ===== helpers =====
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
