"""op-contract-put-warm-pool."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-put-warm-pool"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutWarmPool persists the given warm pool configuration exactly as specified; targeting a
    non-existent Auto Scaling group is rejected and creates no warm pool configuration."""
    autoscaling = ctx.client("autoscaling")
    ami_id = _resolve_ami(ctx)
    subnet_id = _default_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    name = ctx.unique_name("sim2real-behav-warmpool-")
    _create_asg(ctx, name, lt_id, subnet_id, min_size=0, max_size=2, desired=1)

    _poll_until(
        lambda: _group_instances(ctx, name),
        lambda ins: len(ins) == 1 and ins[0]["LifecycleState"] == "InService",
        timeout_s=300.0,
        interval_s=10.0,
    )

    resp = autoscaling.put_warm_pool(
        AutoScalingGroupName=name, MinSize=0, MaxGroupPreparedCapacity=1, PoolState="Stopped"
    )
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected PutWarmPool to return 200, got {status}"

    config = autoscaling.describe_warm_pool(AutoScalingGroupName=name)["WarmPoolConfiguration"]
    assert config["MinSize"] == 0, f"expected MinSize 0, got {config['MinSize']}"
    assert config["MaxGroupPreparedCapacity"] == 1, (
        f"expected MaxGroupPreparedCapacity 1, got {config['MaxGroupPreparedCapacity']}"
    )
    assert config["PoolState"] == "Stopped", f"expected PoolState Stopped, got {config['PoolState']}"

    autoscaling.delete_warm_pool(AutoScalingGroupName=name, ForceDelete=True)
    ctx.on_cleanup(lambda: _try_delete_warm_pool(autoscaling, name))
    _poll_until(
        lambda: autoscaling.describe_warm_pool(AutoScalingGroupName=name).get("WarmPoolConfiguration"),
        lambda cfg: cfg is None,
        timeout_s=120.0,
        interval_s=5.0,
    )

    # Error boundary: PutWarmPool against an Auto Scaling group name that does not exist is
    # rejected, and (since the group never existed) no warm pool configuration is created for it.
    missing_name = ctx.unique_name("sim2real-behav-nogroup-")
    code, message = _error(
        lambda: autoscaling.put_warm_pool(AutoScalingGroupName=missing_name, MinSize=1, PoolState="Stopped")
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = f"AutoScalingGroup name not found - No such Auto Scaling group: {missing_name}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    code2, message2 = _error(lambda: autoscaling.describe_warm_pool(AutoScalingGroupName=missing_name))
    assert code2 == "ValidationError", f"expected ValidationError, got {code2}"
    expected_message = f"AutoScalingGroup name not found - No such Auto Scaling group: {missing_name}"
    assert message2 == expected_message, f"expected message {expected_message!r}, got {message2!r}"


# ===== helpers =====
def _try_delete_warm_pool(autoscaling, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        autoscaling.delete_warm_pool(AutoScalingGroupName=name, ForceDelete=True)
    except ClientError as err:
        error = err.response["Error"]
        message = error.get("Message", "")
        if error["Code"] != "ValidationError" or not ("not found" in message or "No warm pool found" in message):
            raise


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises: the call must be refused."""
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
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
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
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
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
