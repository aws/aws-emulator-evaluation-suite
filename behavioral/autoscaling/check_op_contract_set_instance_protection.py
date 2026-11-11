"""op-contract-set-instance-protection."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-set-instance-protection"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetInstanceProtection toggles Instance.ProtectedFromScaleIn for the named instance in
    both directions; exceeding the documented 50-instance-ID limit is rejected and does not
    change protection on any instance."""
    autoscaling = ctx.client("autoscaling")
    ami_id = _resolve_ami(ctx)
    subnet_id = _default_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    name = ctx.unique_name("sim2real-behav-instprotect-")
    _create_asg(ctx, name, lt_id, subnet_id, min_size=0, max_size=2, desired=1)

    instances = _poll_until(
        lambda: _group_instances(ctx, name),
        lambda ins: len(ins) == 1 and ins[0]["LifecycleState"] == "InService",
        timeout_s=300.0,
        interval_s=10.0,
    )
    instance_id = instances[0]["InstanceId"]
    assert instances[0]["ProtectedFromScaleIn"] is False, (
        f"expected a freshly-launched instance to start unprotected, got "
        f"ProtectedFromScaleIn={instances[0]['ProtectedFromScaleIn']!r}"
    )

    autoscaling.set_instance_protection(
        InstanceIds=[instance_id], AutoScalingGroupName=name, ProtectedFromScaleIn=True
    )
    protected = _poll_until(
        lambda: _group_instances(ctx, name),
        lambda ins: any(i["InstanceId"] == instance_id and i["ProtectedFromScaleIn"] is True for i in ins),
        timeout_s=60.0,
        interval_s=5.0,
    )
    protected_flag = next(i for i in protected if i["InstanceId"] == instance_id)["ProtectedFromScaleIn"]
    assert protected_flag is True, f"expected ProtectedFromScaleIn=True after enabling, got {protected_flag!r}"

    autoscaling.set_instance_protection(
        InstanceIds=[instance_id], AutoScalingGroupName=name, ProtectedFromScaleIn=False
    )
    unprotected = _poll_until(
        lambda: _group_instances(ctx, name),
        lambda ins: any(i["InstanceId"] == instance_id and i["ProtectedFromScaleIn"] is False for i in ins),
        timeout_s=60.0,
        interval_s=5.0,
    )
    unprotected_flag = next(i for i in unprotected if i["InstanceId"] == instance_id)["ProtectedFromScaleIn"]
    assert unprotected_flag is False, f"expected ProtectedFromScaleIn=False after disabling, got {unprotected_flag!r}"

    # Error boundary: the documented limit is 50 instance IDs per call. 51 fabricated IDs
    # (none of which belong to any group) are rejected on the count check, before any per-ID
    # membership validation, and no instance's protection flag changes as a result.
    too_many_ids = [f"i-{i:017x}" for i in range(51)]
    code, message = _error(
        lambda: autoscaling.set_instance_protection(
            InstanceIds=too_many_ids, AutoScalingGroupName=name, ProtectedFromScaleIn=True
        )
    )
    # Real AWS rejects the oversized list as a plain parameter-validation failure, not the
    # account-limit "LimitExceededFault" family of errors.
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = (
        "Exceeded maximum allowed instances to protect simultaneously; can provide at most 50 instances."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    final = _group_instances(ctx, name)
    final_flag = next(i for i in final if i["InstanceId"] == instance_id)["ProtectedFromScaleIn"]
    assert final_flag is False, (
        f"the oversized-list call must not change protection on any instance; "
        f"expected ProtectedFromScaleIn=False, got {final_flag!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _resolve_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    param_name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=param_name)["Parameter"]["Value"]


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in the shared network")
    return subnets[0]["SubnetId"]


def _create_launch_template(ctx, ami_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg(ctx, name: str, lt_id: str, subnet_id: str, min_size: int, max_size: int, desired: int) -> None:
    autoscaling = ctx.client("autoscaling")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True))


def _group_instances(ctx, name: str) -> list[dict[str, Any]]:
    autoscaling = ctx.client("autoscaling")
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    return groups[0]["Instances"] if groups else []


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
