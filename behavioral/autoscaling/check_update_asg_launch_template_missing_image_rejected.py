"""update-asg-launch-template-missing-image-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-asg-launch-template-missing-image-rejected"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]

DEFAULT_INSTANCE_TYPE = "t3.micro"


def _image_id(ctx):
    ssm = ctx.client("ssm")
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=param)["Parameter"]["Value"]


def _subnet_ids(ctx):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    return [s["SubnetId"] for s in sorted(subnets, key=lambda s: s["AvailabilityZone"])[:2]]


def _describe_group(ctx, name):
    as_ = ctx.client("autoscaling")
    groups = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name]).get("AutoScalingGroups", [])
    return groups[0] if groups else None


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    instead: accepting a call AWS refuses is a distinct failure, not an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAutoScalingGroup rejects a launch template without an ImageId with ValidationError and
    leaves the group pointed at its previous, working launch template."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    image_id = _image_id(ctx)
    subnet_ids = _subnet_ids(ctx)

    good_lt_name = ctx.unique_name("sim2real-behav-as-lt-good-")
    good_lt = ec2.create_launch_template(
        LaunchTemplateName=good_lt_name,
        LaunchTemplateData={"ImageId": image_id, "InstanceType": DEFAULT_INSTANCE_TYPE},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=good_lt))

    asg_name = ctx.unique_name("sim2real-behav-as-grp-")
    as_.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": good_lt, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=",".join(subnet_ids),
        HealthCheckGracePeriod=0,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda n=asg_name: as_.delete_auto_scaling_group(AutoScalingGroupName=n, ForceDelete=True))

    before = _describe_group(ctx, asg_name)
    before_spec = before.get("LaunchTemplate") if before else None
    assert before_spec and before_spec["LaunchTemplateId"] == good_lt, (
        f"freshly created group should point at {good_lt!r}, got {before_spec!r}"
    )

    # The second template carries an InstanceType and no ImageId.
    noimg_lt_name = ctx.unique_name("sim2real-behav-as-lt-noimg-")
    noimg_lt = ec2.create_launch_template(
        LaunchTemplateName=noimg_lt_name,
        LaunchTemplateData={"InstanceType": DEFAULT_INSTANCE_TYPE},
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=noimg_lt))

    code, message = _client_error(
        lambda: as_.update_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            LaunchTemplate={"LaunchTemplateId": noimg_lt, "Version": "$Latest"},
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    assert message == (
        "You must use a valid fully-formed launch template. The request must contain the parameter ImageId"
    ), f"expected the exact refusal message, got {message!r}"

    # The rejected update must not have rebased the group onto the incomplete template.
    after_rejection = _describe_group(ctx, asg_name)
    after_spec = after_rejection.get("LaunchTemplate") if after_rejection else None
    assert after_spec and after_spec["LaunchTemplateId"] == good_lt, (
        f"a rejected update must leave the group pointed at {good_lt!r}, got {after_spec!r}"
    )
    assert after_spec["Version"] == "$Latest", (
        f"a rejected update must leave the group's requested version unchanged, got {after_spec.get('Version')!r}"
    )

    # Positive control: the group is not wedged by the rejection — swapping to a second,
    # fully-formed template in the same shape succeeds immediately afterward.
    other_lt_name = ctx.unique_name("sim2real-behav-as-lt-other-")
    other_lt = ec2.create_launch_template(
        LaunchTemplateName=other_lt_name,
        LaunchTemplateData={"ImageId": image_id, "InstanceType": "t3.small"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=other_lt))

    as_.update_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": other_lt, "Version": "$Latest"},
    )
    recovered = _describe_group(ctx, asg_name)
    recovered_spec = recovered.get("LaunchTemplate") if recovered else None
    assert recovered_spec and recovered_spec["LaunchTemplateId"] == other_lt, (
        f"group did not recover after the rejection: LaunchTemplate is {recovered_spec!r}, expected {other_lt!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
