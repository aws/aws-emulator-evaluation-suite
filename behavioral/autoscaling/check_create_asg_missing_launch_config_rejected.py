"""create-asg-missing-launch-config-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "create-asg-missing-launch-config-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAutoScalingGroup with none of LaunchConfigurationName / LaunchTemplate /
    InstanceId / MixedInstancesPolicy supplied (a missing required combination) is rejected
    rather than accepted with some implicit default launch source."""
    autoscaling = ctx.client("autoscaling")
    subnet_id = _default_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)

    asg_name = ctx.unique_name("sim2real-asg-nolc-")
    code, message = _client_error(
        lambda: autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            MinSize=0,
            MaxSize=1,
            DesiredCapacity=0,
            VPCZoneIdentifier=subnet_id,
        )
    )
    assert code == "ValidationError", (
        f"CreateAutoScalingGroup with no launch source returned error code {code!r}, "
        f"expected 'ValidationError'"
    )
    assert message == (
        "Valid requests must contain either LaunchTemplate, LaunchConfigurationName, InstanceId "
        "or MixedInstancesPolicy parameter."
    ), f"expected the exact refusal message, got {message!r}"

    # Effect absent: the group must not have been created.
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert groups == [], (
        f"group {asg_name!r} should not exist after a rejected create, found {groups!r}"
    )

    # Positive control: supplying a launch template succeeds, and reuses the same name that
    # the rejected call above left clean.
    ec2 = ctx.client("ec2")
    lt_name = ctx.unique_name("sim2real-lt-nolc-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )["LaunchTemplate"]
    ctx.on_cleanup(lambda: _safe_call(lambda: ec2.delete_launch_template(
        LaunchTemplateName=lt_name
    )))
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt["LaunchTemplateId"], "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: autoscaling.delete_auto_scaling_group(
        AutoScalingGroupName=asg_name, ForceDelete=True
    )))
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert len(groups) == 1, (
        f"expected exactly one group named {asg_name!r} after the valid create, found {groups!r}"
    )
    assert groups[0]["LaunchTemplate"]["LaunchTemplateId"] == lt["LaunchTemplateId"], (
        f"group {asg_name!r} launch template is {groups[0].get('LaunchTemplate')!r}, "
        f"expected {lt['LaunchTemplateId']!r}"
    )

    # The delete this check's cleanup would otherwise leave unasserted: prove the group is
    # actually gone via an independent read, and that a mutation on the dead name is refused.
    autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    gone = _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ],
        lambda g: g == [],
        timeout_s=60,
        description=f"group {asg_name!r} disappearing after delete",
    )
    assert gone == [], f"group {asg_name!r} still present after delete: {gone!r}"

    dead_code, dead_message = _client_error(
        lambda: autoscaling.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=1)
    )
    assert dead_code == "ValidationError", (
        f"SetDesiredCapacity on the deleted group {asg_name!r} returned {dead_code!r}, "
        f"expected 'ValidationError'"
    )
    assert dead_message == "AutoScalingGroup name not found - null", f"expected the exact refusal message, got {dead_message!r}"


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


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, because accepting a call AWS refuses is itself the failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float = 3.0,
    description: str = "condition",
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
