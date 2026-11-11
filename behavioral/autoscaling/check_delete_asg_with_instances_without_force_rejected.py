"""delete-asg-with-instances-without-force-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-asg-with-instances-without-force-rejected"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAutoScalingGroup without ForceDelete is rejected with ResourceInUse while the group
    has instances; the identical call succeeds on an empty group and on the same group once
    drained, so the block is the instance, not the API path or the credentials."""
    asg = ctx.client("autoscaling")
    subnet = _default_subnet(ctx)
    ami_id = _al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id)

    # Positive control: an empty group is not "in use" and the unforced delete succeeds.
    control_name = ctx.unique_name("sim2real-behav-asg-ctrl-")
    _create_asg(ctx, control_name, lt_id, min_size=0, max_size=1, desired=0, subnet_id=subnet["subnet_id"])
    asg.delete_auto_scaling_group(AutoScalingGroupName=control_name)
    _poll_until(
        lambda: asg.describe_auto_scaling_groups(AutoScalingGroupNames=[control_name])["AutoScalingGroups"],
        lambda groups: not groups,
        timeout_s=120,
        interval_s=5,
        what=f"positive-control group {control_name} to disappear after its accepted delete",
    )

    group_name = ctx.unique_name("sim2real-behav-asg-")
    _create_asg(ctx, group_name, lt_id, min_size=1, max_size=1, desired=1, subnet_id=subnet["subnet_id"])

    _poll_until(
        lambda: _describe_group(ctx, group_name)["Instances"],
        lambda instances: any(i["LifecycleState"] == "InService" for i in instances),
        timeout_s=300,
        interval_s=5,
        what=f"an InService instance in {group_name}",
    )

    code, message = _error_code(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name))
    assert code == "ResourceInUse", f"expected ResourceInUse deleting a non-empty group without ForceDelete, got {code!r}"
    assert message == _RESOURCE_IN_USE_MESSAGE, (
        f"expected the exact non-empty-group refusal message, got {message!r}"
    )

    # The group must still be describable (delete was rejected, not silently accepted).
    still_there = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
    assert still_there, "group disappeared even though the non-forced delete should have been rejected"

    # Restore: drain the group back to empty, then the identical call must now succeed.
    asg.update_auto_scaling_group(AutoScalingGroupName=group_name, MinSize=0, DesiredCapacity=0)
    _poll_until(
        lambda: _describe_group(ctx, group_name)["Instances"],
        lambda instances: not instances,
        timeout_s=300,
        interval_s=5,
        what=f"{group_name} to drain to zero instances",
    )

    asg.delete_auto_scaling_group(AutoScalingGroupName=group_name)

    _poll_until(
        lambda: asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"],
        lambda groups: not groups,
        timeout_s=120,
        interval_s=5,
        what=f"{group_name} to disappear after its now-empty group's delete succeeded",
    )

    dead_code, dead_message = _error_code(
        lambda: asg.update_auto_scaling_group(AutoScalingGroupName=group_name, MinSize=0)
    )
    assert dead_code == "ValidationError", f"expected ValidationError updating a deleted group, got {dead_code!r}"
    assert dead_message == "AutoScalingGroup name not found - null", (
        f"expected the exact group-not-found message updating a deleted group, got {dead_message!r}"
    )


# ===== helpers =====
_RESOURCE_IN_USE_MESSAGE = (
    "You cannot delete an AutoScalingGroup while there are instances or pending Spot instance "
    "request(s) still in the group."
)


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises,
    because a target accepting a delete real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0, what="condition"):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if predicate(result):
        return result
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last observed: {result!r}")


def _describe_group(ctx, group_name: str) -> dict:
    asg = ctx.client("autoscaling")
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
    assert groups, f"group {group_name} not found"
    return groups[0]


def _default_subnet(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet = subnets[0]
    return {"vpc_id": vpc_id, "subnet_id": subnet["SubnetId"]}


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
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
        ],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg(ctx, name: str, lt_id: str, min_size: int, max_size: int, desired: int, subnet_id: str, **kwargs):
    asg = ctx.client("autoscaling")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real-check", "Value": CHECK, "PropagateAtLaunch": False}],
        **kwargs,
    )

    def _cleanup():
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
                raise

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
