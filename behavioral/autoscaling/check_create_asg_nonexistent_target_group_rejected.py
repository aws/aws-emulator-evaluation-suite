"""create-asg-nonexistent-target-group-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-asg-nonexistent-target-group-rejected"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAutoScalingGroup rejects a well-formed but nonexistent target group ARN in
    TargetGroupARNs and creates no group, while the same request against a real target
    group succeeds."""
    asg = ctx.client("autoscaling")
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    ami_id = _latest_al2023_ami(ctx)
    subnet_id, vpc_id = _default_subnet(ctx)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    missing_name = ctx.unique_name("sim2real-behav-asg-missing-")
    fake_arn = (
        f"arn:aws:elasticloadbalancing:{ctx.region}:{ctx.account}:"
        f"targetgroup/sim2real-behav-nonexistent-{uuid.uuid4().hex[:12]}/0123456789abcdef"
    )
    code, message = _error(
        lambda: asg.create_auto_scaling_group(
            AutoScalingGroupName=missing_name,
            LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
            MinSize=0,
            MaxSize=1,
            DesiredCapacity=0,
            VPCZoneIdentifier=subnet_id,
            TargetGroupARNs=[fake_arn],
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = "Provided Target Groups may not be valid. Please ensure they exist and try again."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    describe_after_reject = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[missing_name])[
        "AutoScalingGroups"
    ]
    assert describe_after_reject == [], (
        f"a rejected CreateAutoScalingGroup must create no group, found {describe_after_reject!r}"
    )

    tg_name = ctx.unique_name("sim2real-behav-tg-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance"
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    real_name = ctx.unique_name("sim2real-behav-asg-real-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=real_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        TargetGroupARNs=[tg_arn],
    )
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=real_name, ForceDelete=True))

    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[real_name])["AutoScalingGroups"]
    assert len(groups) == 1, f"expected the real target group create to succeed, got {groups!r}"
    assert groups[0]["TargetGroupARNs"] == [tg_arn], (
        f"expected TargetGroupARNs [{tg_arn}], got {groups[0]['TargetGroupARNs']!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameter"]["Value"]


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in the shared network")
    return subnets[0]["SubnetId"], subnets[0]["VpcId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
