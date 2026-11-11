"""create-auto-scaling-group-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-auto-scaling-group-duplicate-name-rejected"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAutoScalingGroup rejects a second group using a name that already exists in
    the account/Region with AlreadyExists, the original group is left untouched, and a
    subsequent create using a genuinely unused name still succeeds (positive control)."""
    asg = ctx.client("autoscaling")
    subnet_id = _default_subnet(ctx)
    ami_id = _al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id)

    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )

    def _cleanup_group(name):
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
                raise

    ctx.on_cleanup(lambda: _cleanup_group(group_name))

    code, message = _error_code(
        lambda: asg.create_auto_scaling_group(
            AutoScalingGroupName=group_name,
            LaunchTemplate={"LaunchTemplateId": lt_id},
            MinSize=0,
            MaxSize=1,
            DesiredCapacity=0,
            VPCZoneIdentifier=subnet_id,
        )
    )
    assert code == "AlreadyExists", f"expected AlreadyExists creating a duplicate group name, got {code!r}"
    expected_message = (
        f"AutoScalingGroup by this name already exists - A group with the name {group_name} already exists"
    )
    assert message == expected_message, f"expected the exact duplicate-name message, got {message!r}"

    unchanged = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
    assert len(unchanged) == 1, f"expected exactly one group with that name, found {len(unchanged)}"
    assert unchanged[0]["MinSize"] == 0, f"original group's MinSize was mutated by the rejected duplicate create: {unchanged[0]['MinSize']}"
    assert unchanged[0]["MaxSize"] == 0, f"original group's MaxSize was mutated by the rejected duplicate create: {unchanged[0]['MaxSize']}"
    assert unchanged[0]["DesiredCapacity"] == 0, f"original group's DesiredCapacity was mutated by the rejected duplicate create: {unchanged[0]['DesiredCapacity']}"

    # Positive control: CreateAutoScalingGroup still works for a genuinely unused name,
    # so the rejection above is specific to the duplicate name and not a broken/denied API.
    other_name = ctx.unique_name("sim2real-behav-asg-other-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=other_name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: _cleanup_group(other_name))
    created = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[other_name])["AutoScalingGroups"]
    assert len(created) == 1, f"expected the freshly-named group to exist, got {created}"


# ===== helpers =====
def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises,
    because a target accepting a duplicate name real AWS refuses must not read as a code
    mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the duplicate-name create to be rejected, but it SUCCEEDED: {result!r}")


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    return subnets[0]["SubnetId"]


def _al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    try:
        name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        return ssm.get_parameter(Name=name)["Parameter"]["Value"]
    except Exception:
        ec2 = ctx.client("ec2")
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
            ],
        )["Images"]
        images.sort(key=lambda im: im["CreationDate"], reverse=True)
        return images[0]["ImageId"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    resp = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
