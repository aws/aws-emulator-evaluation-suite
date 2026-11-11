"""asg-min-size-exceeds-max-size-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "asg-min-size-exceeds-max-size-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAutoScalingGroup with MinSize > MaxSize is rejected outright, leaves no
    group behind, and the identical name/config succeeds once the range is fixed."""
    autoscaling = ctx.client("autoscaling")

    _vpc_id, subnet_ids, sg_id = _default_vpc_subnets(ctx)
    ami = _al2_ami_id(ctx)

    lt_name = ctx.unique_name("sim2real-lt-")
    ec2 = ctx.client("ec2")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro", "SecurityGroupIds": [sg_id]},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-asg-")

    code, message = _client_error(lambda: autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name, LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=5, MaxSize=2, DesiredCapacity=3,
        VPCZoneIdentifier=subnet_ids[0],
    ))
    assert code == "ValidationError", f"expected ValidationError for MinSize > MaxSize, got {code!r}"
    assert message == "Max bound, 2, must be greater than or equal to min bound, 5", f"expected the exact refusal message, got {message!r}"

    # effect absent: no group with this name exists
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    assert groups == [], f"the rejected create should not have left a group behind, found {groups!r}"

    # positive control: the exact same name/config with a valid range succeeds
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name, LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=1, MaxSize=2, DesiredCapacity=1,
        VPCZoneIdentifier=subnet_ids[0],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))
    created = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    assert len(created) == 1, f"expected exactly one group named {asg_name!r} after the valid create, found {created!r}"
    actual = (created[0]["MinSize"], created[0]["MaxSize"], created[0]["DesiredCapacity"])
    assert actual == (1, 2, 1), f"expected (MinSize, MaxSize, DesiredCapacity) == (1, 2, 1), got {actual!r}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _al2_ami_id(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"]["Value"]


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, [s["SubnetId"] for s in subnets], sg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
