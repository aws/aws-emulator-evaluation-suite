"""tag-resourcetype-other-than-auto-scaling-group-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resourcetype-other-than-auto-scaling-group-rejected"
GROUP = "tags"
SERVICES = ["autoscaling"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_zero_capacity_group(ctx, asg) -> str:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami_id = ssm.get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")

    lt_name = ctx.unique_name("sim2real-behav-tagrt-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    group_name = ctx.unique_name("sim2real-behav-tagrt-grp-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnets[0]["SubnetId"],
    )
    ctx.on_cleanup(
        lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True)
    )
    return group_name


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOrUpdateTags with a ResourceType other than the one supported value
    auto-scaling-group is rejected and stores nothing; the identical tag with the
    correct ResourceType is accepted and round-trips through DescribeTags."""
    asg = ctx.client("autoscaling")
    group_name = _create_zero_capacity_group(ctx, asg)
    key = "cost-center"

    code, message = _error(
        lambda: asg.create_or_update_tags(
            Tags=[
                {
                    "ResourceId": group_name,
                    "ResourceType": "autoscaling-group",
                    "Key": key,
                    "Value": "finance",
                    "PropagateAtLaunch": False,
                }
            ]
        )
    )
    assert code == "ValidationError", f"an unsupported ResourceType gave {code}: {message!r}"
    expected_message = (
        "Invalid resourceType: autoscaling-group. Valid resource types are: auto-scaling-group "
    )
    assert message == expected_message, (
        f"unexpected message for an unsupported ResourceType: {message!r}"
    )

    present = asg.describe_tags(
        Filters=[{"Name": "auto-scaling-group", "Values": [group_name]}]
    )["Tags"]
    assert present == [], f"a rejected tag must not be stored, got {present}"

    asg.create_or_update_tags(
        Tags=[
            {
                "ResourceId": group_name,
                "ResourceType": "auto-scaling-group",
                "Key": key,
                "Value": "finance",
                "PropagateAtLaunch": False,
            }
        ]
    )
    present = asg.describe_tags(
        Filters=[{"Name": "auto-scaling-group", "Values": [group_name]}]
    )["Tags"]
    assert len(present) == 1 and present[0]["Key"] == key, present


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
