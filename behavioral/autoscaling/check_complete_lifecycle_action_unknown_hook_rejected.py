"""complete-lifecycle-action-unknown-hook-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-lifecycle-action-unknown-hook-rejected"
GROUP = 'error-semantics'
SERVICES = ['autoscaling']

def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, because accepting a call AWS refuses is itself the failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _unless_gone(fn) -> None:
    """Run a teardown step; only Auto Scaling's "not found" ValidationError means already gone."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        msg = err.get("Message", "")
        if not (err["Code"] == "ValidationError" and ("not found" in msg or "No Lifecycle Hook found" in msg)):
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _instances_in_group(as_, name):
    return as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name])[
        "AutoScalingGroups"
    ][0]["Instances"]


def _state_of(as_, name, instance_id):
    for inst in _instances_in_group(as_, name):
        if inst["InstanceId"] == instance_id:
            return inst["LifecycleState"]
    return "absent"


_AL2023_SSM_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
# DescribeImages fallback when the execution role has no ssm:GetParameter.
_AMI_NAME_PATTERNS = (
    "al2023-ami-2023.*-kernel-6.1-x86_64",
    "al2023-ami-*-x86_64",
    "amzn2-ami-hvm-*-x86_64-gp2",
)
_CANDIDATE_INSTANCE_TYPES = ("t3.micro", "t2.micro", "t3a.micro")
# Stamped on every resource this check creates so leftovers can be found and reaped.
_MANAGED_TAG_KEY = "sim2real:managed"


def _resolve_ami(ec2, ssm) -> str:
    """Resolve a real, bootable x86_64 Amazon Linux AMI id: the public SSM alias, else the newest
    Amazon-owned image from DescribeImages (the role may lack ssm:GetParameter).
    """
    errors: list[str] = []
    try:
        return ssm.get_parameter(Name=_AL2023_SSM_PARAM)["Parameter"]["Value"]
    except Exception as exc:  # noqa: BLE001
        errors.append(f"ssm:{exc}")

    for name_pattern in _AMI_NAME_PATTERNS:
        try:
            images = ec2.describe_images(
                Owners=["amazon"],
                Filters=[
                    {"Name": "name", "Values": [name_pattern]},
                    {"Name": "state", "Values": ["available"]},
                    {"Name": "architecture", "Values": ["x86_64"]},
                    {"Name": "root-device-type", "Values": ["ebs"]},
                    {"Name": "virtualization-type", "Values": ["hvm"]},
                ],
            ).get("Images", [])
        except Exception as exc:  # noqa: BLE001
            errors.append(f"describe_images({name_pattern}):{exc}")
            continue
        if images:
            return max(images, key=lambda i: i.get("CreationDate", ""))["ImageId"]
        errors.append(f"describe_images({name_pattern}):no images")

    raise AssertionError(f"could not resolve a bootable AMI id ({'; '.join(errors)})")


def _network(ec2, *, ctx) -> tuple[str, str, str, str]:
    """(subnet_id, az, instance_type, vpc_id) for a placeable Auto Scaling group."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get(
        "Subnets", []
    )
    if not subnets:
        raise AssertionError(f"no subnets in VPC {vpc_id}")

    offered: set[tuple[str, str]] = set()
    try:
        resp = ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": list(_CANDIDATE_INSTANCE_TYPES)}, {"Name": "location", "Values": ctx.network().availability_zones}],
            MaxResults=1000,
        )
        offered = {
            (o["InstanceType"], o["Location"]) for o in resp.get("InstanceTypeOfferings", [])
        }
    except Exception:  # noqa: BLE001 - best effort; fall back to first subnet
        offered = set()

    for itype in _CANDIDATE_INSTANCE_TYPES:
        for subnet in subnets:
            az = subnet["AvailabilityZone"]
            if not offered or (itype, az) in offered:
                return subnet["SubnetId"], az, itype, vpc_id
    raise AssertionError("no subnet/instance-type combination available")


def _discover_env(ctx):
    """One-shot AMI / subnet / instance-type discovery shared by every group this check builds."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    subnet_id, _az, instance_type, _vpc_id = _network(ec2, ctx=ctx)
    return {
        "ec2": ec2,
        "ami": _resolve_ami(ec2, ssm),
        "subnet": subnet_id,
        "instance_type": instance_type,
    }


def _delete_launch_template(ec2, name) -> None:
    """Delete a launch template, retrying while a still-draining group pins it.

    ForceDelete returns before the group is gone, so a refusal is retried for 30 s, then raised.
    """
    deadline = time.monotonic() + 30
    while True:
        try:
            ec2.delete_launch_template(LaunchTemplateName=name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidLaunchTemplateName.NotFoundException":
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _make_launch_template(ctx, env) -> str:
    """Create an EC2 launch template usable by an Auto Scaling group."""
    name = ctx.unique_name("sim2real-behav-asg-lt-")
    env["ec2"].create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": env["ami"], "InstanceType": env["instance_type"]},
    )
    ctx.on_cleanup(lambda: _delete_launch_template(env["ec2"], name))
    return name


def _make_group(
    ctx,
    as_,
    env,
    *,
    min_size: int = 0,
    max_size: int = 2,
    desired_capacity=None,
    launch_template=None,
    **overrides,
) -> str:
    """Create an Auto Scaling group (and, unless given one, its launch template)."""
    name = ctx.unique_name("sim2real-behav-asg-grp-")
    params: dict = {
        "AutoScalingGroupName": name,
        "MinSize": min_size,
        "MaxSize": max_size,
        "VPCZoneIdentifier": env["subnet"],
        "HealthCheckType": "EC2",
        "HealthCheckGracePeriod": 0,
        "DefaultCooldown": 0,
        "Tags": [{"Key": _MANAGED_TAG_KEY, "Value": "true", "PropagateAtLaunch": True}],
    }
    lt = launch_template or _make_launch_template(ctx, env)
    params["LaunchTemplate"] = {"LaunchTemplateName": lt, "Version": "$Latest"}
    if desired_capacity is not None:
        params["DesiredCapacity"] = desired_capacity
    params.update(overrides)
    as_.create_auto_scaling_group(**params)
    ctx.on_cleanup(
        lambda: as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    )
    return name

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RecordLifecycleActionHeartbeat and CompleteLifecycleAction reject an unknown hook name with
    an exact ValidationError and leave the instance at Pending:Wait, while the same calls on the
    real hook succeed (the heartbeat keeps the hold, the completion releases it).
    """
    as_ = ctx.client("autoscaling")
    env = _discover_env(ctx)

    name = _make_group(ctx, as_, env, min_size=0, max_size=1, desired_capacity=0)
    ghost = ctx.unique_name("sim2real-behav-asg-nohook-")

    hook_name = ctx.unique_name("sim2real-behav-asg-hook-")
    as_.put_lifecycle_hook(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        HeartbeatTimeout=300,
        DefaultResult="CONTINUE",
    )
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: as_.delete_lifecycle_hook(
                LifecycleHookName=hook_name, AutoScalingGroupName=name
            )
        )
    )

    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1, HonorCooldown=False)
    instances = _poll_until(
        lambda: _instances_in_group(as_, name),
        lambda insts: any(i["LifecycleState"] == "Pending:Wait" for i in insts),
        timeout_s=300,
        description="an instance held at Pending:Wait by the launching hook",
    )
    instance_id = next(i["InstanceId"] for i in instances if i["LifecycleState"] == "Pending:Wait")

    # --- RecordLifecycleActionHeartbeat: unknown hook rejected, correct hook accepted.
    code, message = _client_error(
        lambda: as_.record_lifecycle_action_heartbeat(
            LifecycleHookName=ghost,
            AutoScalingGroupName=name,
            InstanceId=instance_id,
        )
    )
    assert code == "ValidationError", (
        f"RecordLifecycleActionHeartbeat with an unknown hook: expected ValidationError, got {code}"
    )
    assert message == (
        f"No active Lifecycle Action found with instance ID {instance_id} and HookName {ghost}"
    ), f"expected the exact refusal message, got {message!r}"

    as_.record_lifecycle_action_heartbeat(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=name,
        InstanceId=instance_id,
    )
    state_after_heartbeat = _state_of(as_, name, instance_id)
    assert state_after_heartbeat == "Pending:Wait", (
        "a heartbeat on the correct hook must not itself release the instance, got "
        f"{state_after_heartbeat!r}"
    )

    # --- CompleteLifecycleAction: unknown hook rejected, correct hook accepted.
    code, message = _client_error(
        lambda: as_.complete_lifecycle_action(
            LifecycleHookName=ghost,
            AutoScalingGroupName=name,
            LifecycleActionResult="CONTINUE",
            InstanceId=instance_id,
        )
    )
    assert code == "ValidationError", (
        f"CompleteLifecycleAction with an unknown hook: expected ValidationError, got {code}"
    )
    assert message == (
        f"No active Lifecycle Action found with instance ID {instance_id} and HookName {ghost}"
    ), f"expected the exact refusal message, got {message!r}"
    state_after_rejected_complete = _state_of(as_, name, instance_id)
    assert state_after_rejected_complete == "Pending:Wait", (
        "the refused CompleteLifecycleAction on an unknown hook must not have released the "
        f"instance held by the real hook, got {state_after_rejected_complete!r}"
    )

    as_.complete_lifecycle_action(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=name,
        LifecycleActionResult="CONTINUE",
        InstanceId=instance_id,
    )
    final_state = _poll_until(
        lambda: _state_of(as_, name, instance_id),
        lambda s: s != "Pending:Wait",
        timeout_s=180,
        description="the correctly-addressed CompleteLifecycleAction released the instance",
    )
    assert final_state != "Pending:Wait", (
        f"CompleteLifecycleAction on the correct hook did not release the instance: {final_state!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
