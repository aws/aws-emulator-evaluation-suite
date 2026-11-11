"""create-auto-scaling-group-min-exceeds-max-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-auto-scaling-group-min-exceeds-max-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAutoScalingGroup rejects a request whose MinSize exceeds its MaxSize with
    ValidationError and creates nothing; the identical request with MinSize<=MaxSize
    (positive control) succeeds and the group becomes describable."""
    autoscaling = ctx.client("autoscaling")
    lt_name = _create_launch_template(ctx)
    subnet_id = _get_default_subnet_id(ctx)
    launch_template = {"LaunchTemplateName": lt_name, "Version": "$Latest"}

    # Positive control: a valid MinSize<=MaxSize group is accepted and created.
    good_name = ctx.unique_name("sim2real-behav-asg-good-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=good_name,
        LaunchTemplate=launch_template,
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=good_name, ForceDelete=True)
    )
    described_good = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[good_name])
    assert len(described_good["AutoScalingGroups"]) == 1, (
        f"positive control {good_name!r} did not become describable: "
        f"{described_good['AutoScalingGroups']!r}"
    )

    # Negative: MinSize (2) exceeds MaxSize (1) -> rejected, nothing created.
    bad_name = ctx.unique_name("sim2real-behav-asg-bad-")
    code, message, status = _error_code(
        lambda: autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=bad_name,
            LaunchTemplate=launch_template,
            MinSize=2,
            MaxSize=1,
            DesiredCapacity=2,
            VPCZoneIdentifier=subnet_id,
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    assert status == 400, f"expected HTTP 400 for MinSize>MaxSize, got {status!r}"
    expected_message = "Max bound, 1, must be greater than or equal to min bound, 2"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    described_bad = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[bad_name])
    assert described_bad["AutoScalingGroups"] == [], "rejected group must not have been created"


def _error_code(fn):
    """Call fn(); return its botocore error code, message and HTTP status. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""), status
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


#: Latest Amazon Linux 2023 AMI from the public SSM parameter.
_CATALOG_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


def _catalog_ami(ctx) -> str:
    """Latest Amazon Linux 2023 AMI, resolved via GetParameter on the public SSM parameter."""
    from botocore.exceptions import ClientError

    try:
        return ctx.client("ssm").get_parameter(Name=_CATALOG_AMI_PARAM)["Parameter"]["Value"]
    except ClientError as exc:
        raise AssertionError(
            f"prerequisite catalog-ami: GetParameter({_CATALOG_AMI_PARAM}) failed: {exc}"
        ) from exc


def _create_launch_template(ctx) -> str:
    """AWS no longer allows CreateLaunchConfiguration in most accounts ("Use launch
    templates to create configuration templates for your Auto Scaling groups."), so
    every group in this check is backed by an EC2 launch template instead."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": _catalog_ami(ctx), "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _get_default_subnet_id(ctx) -> str:

    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no default-for-az subnet available in this account/region")
    return subnets[0]["SubnetId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
