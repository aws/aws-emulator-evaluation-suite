"""rollback-instance-refresh-irreversible-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "rollback-instance-refresh-irreversible-fails"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RollbackInstanceRefresh on a group pinned to launch template '$Latest' fails with
    IrreversibleInstanceRefresh (unsupported for $Latest/$Default), and the active refresh is not
    switched into a rollback state."""
    asg = ctx.client("autoscaling")
    ctx.client("ec2")

    ami_id = _latest_al2023_ami(ctx)
    subnet = _default_subnet(ctx)
    lt_name = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-asg-")

    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        MinSize=1,
        MaxSize=1,
        DesiredCapacity=1,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        VPCZoneIdentifier=subnet["subnet_id"],
        HealthCheckType="EC2",
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: _delete_group(ctx, group_name))

    # Wait for the single instance to reach InService before refreshing it.
    in_service = _poll_until(
        lambda: [
            i
            for i in asg.describe_auto_scaling_groups(
                AutoScalingGroupNames=[group_name]
            )["AutoScalingGroups"][0]["Instances"]
            if i["LifecycleState"] == "InService"
        ],
        lambda instances: len(instances) == 1,
        timeout_s=240.0,
        interval_s=5.0,
    )
    assert len(in_service) == 1, "instance never reached InService"

    refresh_id = asg.start_instance_refresh(AutoScalingGroupName=group_name)[
        "InstanceRefreshId"
    ]

    def _latest_refresh():
        return asg.describe_instance_refreshes(
            AutoScalingGroupName=group_name, InstanceRefreshIds=[refresh_id]
        )["InstanceRefreshes"][0]

    active = _poll_until(
        _latest_refresh,
        lambda r: r["Status"] in ("Pending", "InProgress", "Baking"),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert active["Status"] in ("Pending", "InProgress", "Baking"), (
        f"refresh must be active before attempting rollback, was "
        f"{active['Status']}"
    )

    code, message = _error(lambda: asg.rollback_instance_refresh(AutoScalingGroupName=group_name))
    assert code == "IrreversibleInstanceRefresh", (
        f"expected IrreversibleInstanceRefresh for a $Latest-pinned group, got {code}"
    )
    expected = ("This Auto Scaling group's launch template version isn't compatible with a rollback. "
                "Rollbacks are not supported when the Auto Scaling group uses the launch template's "
                "'$Latest' or '$Default' version.")
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The rejected rollback must not have flipped the refresh into a
    # rollback state.
    after = _latest_refresh()
    assert after["Status"] not in ("RollbackInProgress", "RollbackSuccessful", "RollbackFailed"), (
        f"refresh must not enter a rollback state after a rejected "
        f"RollbackInstanceRefresh call, was {after['Status']}"
    )

    # Clean up the still-active refresh before tearing down the group.
    try:
        asg.cancel_instance_refresh(AutoScalingGroupName=group_name)
    except Exception:
        pass
    _poll_until(
        _latest_refresh,
        lambda r: r["Status"] in ("Cancelled", "Successful", "Failed"),
        timeout_s=180.0,
        interval_s=5.0,
    )




def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _error(fn):
    """Call fn(); return its botocore error (code, message). Raises if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _default_subnet(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    subnet = subnets[0]
    return {"subnet_id": subnet["SubnetId"], "az": subnet["AvailabilityZone"]}


def _create_launch_template(ctx, ami_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _delete_group(ctx, group_name: str) -> None:
    from botocore.exceptions import ClientError

    asg = ctx.client("autoscaling")
    try:
        asg.delete_auto_scaling_group(
            AutoScalingGroupName=group_name, ForceDelete=True
        )
    except ClientError as err:
        error = err.response["Error"]
        if error["Code"] != "ValidationError" or "not found" not in error.get("Message", ""):
            raise
        return
    _poll_until(
        lambda: len(
            asg.describe_auto_scaling_groups(
                AutoScalingGroupNames=[group_name]
            )["AutoScalingGroups"]
        ),
        lambda n: n == 0,
        timeout_s=180.0,
        interval_s=5.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
