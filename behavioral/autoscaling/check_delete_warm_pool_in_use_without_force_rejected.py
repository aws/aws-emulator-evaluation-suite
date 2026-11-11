"""delete-warm-pool-in-use-without-force-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-warm-pool-in-use-without-force-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWarmPool without ForceDelete while the warm pool still has instances must fail
    with ResourceInUseFault, not silently delete the configuration out from under the live
    instances."""
    asg = ctx.client("autoscaling")
    subnet_id = _get_default_subnet(ctx)
    ami_id = _get_al2_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id=ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: _delete_asg_force(ctx, group_name))

    asg.put_warm_pool(AutoScalingGroupName=group_name, MinSize=1, PoolState="Stopped")
    ctx.on_cleanup(lambda: _unless_gone(lambda: asg.delete_warm_pool(AutoScalingGroupName=group_name, ForceDelete=True)))

    def _warm_pool_instances_probe():
        return asg.describe_warm_pool(AutoScalingGroupName=group_name).get("Instances", [])

    instances = _poll_until(
        _warm_pool_instances_probe,
        lambda items: len(items) >= 1 and all(i["LifecycleState"] == "Warmed:Stopped" for i in items),
        timeout_s=300,
        interval_s=10,
    )
    assert instances, "warm pool never provisioned any instances"

    # DeleteWarmPool can transiently report ScalingActivityInProgressFault while the warm
    # pool instances are still settling into their terminal state, or ResourceContentionFault
    # if it races with the PutWarmPool call that just finished converging the pool; retry
    # through both transient conditions and only assert on the steady-state response.
    #
    # Note: AWS's awsQuery-protocol error responses report the wire-level Error.Code
    # without the "Fault" suffix that botocore's generated exception class carries (e.g.
    # the modeled shape "ResourceInUseFault" is returned on the wire as "ResourceInUse").
    # Compare/retry against the actual wire codes, not the exception class names.
    _TRANSIENT_CODES = {"ScalingActivityInProgress", "ResourceContention"}

    def _delete_attempt():
        return _error(lambda: asg.delete_warm_pool(AutoScalingGroupName=group_name))

    error = _poll_until(
        _delete_attempt,
        lambda e: e.get("Code") not in _TRANSIENT_CODES,
        timeout_s=120,
        interval_s=5,
    )
    code = error.get("Code")
    assert code == "ResourceInUse", f"expected ResourceInUse, got {code!r}"
    expected = (
        "You cannot delete a warm pool while there are instances still in it unless you use "
        "the force delete option."
    )
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"

    # ForceDelete=True must actually work (confirms the failure above was state-specific, not blanket)
    asg.delete_warm_pool(AutoScalingGroupName=group_name, ForceDelete=True)

    remaining = _poll_until(
        _warm_pool_instances_probe,
        lambda items: len(items) == 0,
        timeout_s=120,
        interval_s=5,
    )
    assert remaining == [], (
        f"warm pool still reports instances via an independent describe_warm_pool call "
        f"after ForceDelete=True removed it: {remaining!r}"
    )


# ===== helpers =====


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, so a target
    that deletes the warm pool out from under live instances is not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"DeleteWarmPool without ForceDelete unexpectedly succeeded while instances existed: {result!r}"
    )


def _unless_gone(fn) -> None:
    """Run a teardown delete; only "not found" / "No warm pool found" means already gone."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        msg = err.get("Message", "")
        if not (err["Code"] == "ValidationError" and ("not found" in msg or "No warm pool found" in msg)):
            raise


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _get_default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return subnets[0]["SubnetId"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
        TagSpecifications=[
            {
                "ResourceType": "launch-template",
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            }
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _delete_asg_force(ctx, name: str) -> None:
    """Force-delete the group, retrying in-progress refusals for 60 s; only "not found" means gone."""
    asg = ctx.client("autoscaling")
    deadline = time.monotonic() + 60
    while True:
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ValidationError" and "not found" in err.response["Error"].get("Message", ""):
                return
            if code not in ("ScalingActivityInProgress", "ResourceContention", "ResourceInUse"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
