"""create-asg-negative-min-size-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "create-asg-negative-min-size-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAutoScalingGroup with a negative MinSize (malformed, out-of-range numeric input)
    is rejected rather than silently clamped to zero or otherwise accepted."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    subnet_id = _default_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)

    lt_name = ctx.unique_name("sim2real-lt-negmin-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]
    ctx.on_cleanup(lambda: _safe_call(lambda: ec2.delete_launch_template(
        LaunchTemplateName=lt_name
    )))

    asg_name = ctx.unique_name("sim2real-asg-negmin-")

    code, message = _error_code(
        lambda: autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            LaunchTemplate={"LaunchTemplateId": lt["LaunchTemplateId"], "Version": "$Latest"},
            MinSize=-1,
            MaxSize=3,
            VPCZoneIdentifier=subnet_id,
        )
    )
    assert code == "ValidationError", f"expected ValidationError for MinSize=-1, got {code!r}"
    assert message == "Min bound, -1, must be non-negative", (
        f"expected the exact MinSize=-1 refusal message, got {message!r}"
    )

    # Effect absent: the group must not have been created.
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert groups == [], f"expected no group named {asg_name!r} after rejection, found {groups!r}"

    # Positive control: the same call with a valid (non-negative) MinSize succeeds.
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt["LaunchTemplateId"], "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[
            {"Key": "sim2real-check", "Value": CHECK, "PropagateAtLaunch": False, "ResourceId": asg_name, "ResourceType": "auto-scaling-group"}
        ],
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: autoscaling.delete_auto_scaling_group(
        AutoScalingGroupName=asg_name, ForceDelete=True
    )))
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert len(groups) == 1, f"expected exactly one group named {asg_name!r}, found {groups!r}"
    assert groups[0]["MinSize"] == 0, f"expected MinSize=0 on the positive control, got {groups[0]['MinSize']!r}"


# ===== helpers =====
def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if not subnets:
        raise AssertionError(
            "no shared-network subnet found in this account/region to build a valid create request"
        )
    return subnets[0]["SubnetId"]


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]


def _safe_call(fn: Callable[[], Any]) -> None:
    """Run a teardown delete; only a not-found error means already gone, anything else raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] in _NOT_FOUND_CODES:
            return
        if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
            raise


_NOT_FOUND_CODES = ("InvalidLaunchTemplateName.NotFoundException", "InvalidLaunchTemplateId.NotFound")


def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    accepting input AWS refuses is itself the failure (and leaves a group no cleanup covers)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected CreateAutoScalingGroup with MinSize=-1 to be rejected, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
