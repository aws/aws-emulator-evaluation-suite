"""concurrent-capacity-provider-update-contention."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-capacity-provider-update-contention"
GROUP = 'concurrency'
SERVICES = ['ecs']


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


def _create_shell_capacity_provider(ctx, ecs, *, managed_scaling=None):
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    autoscaling = ctx.client("autoscaling")
    ami_id = ssm.get_parameter(
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
    )["Parameter"]["Value"]
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"][0]["ZoneName"]
    lt_name = ctx.unique_name("sim2real-behav-ecs-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))
    asg_name = ctx.unique_name("sim2real-behav-ecs-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )
    asg_arn = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]["AutoScalingGroupARN"]
    cp_name = ctx.unique_name("sim2real-behav-ecs-cp-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": managed_scaling or {"status": "DISABLED"},
            "managedTerminationProtection": "DISABLED",
        },
    )
    ctx.on_cleanup(lambda: ecs.delete_capacity_provider(capacityProvider=cp_name))
    return cp_name


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateCapacityProvider calls setting different targetCapacity values on the
    same provider: at least one applies, and the settled state matches exactly one racing value."""
    ecs = ctx.client("ecs")
    cp_name = _create_shell_capacity_provider(ctx, ecs)

    def _update(target):
        return ecs.update_capacity_provider(
            name=cp_name,
            autoScalingGroupProvider={"managedScaling": {"status": "ENABLED", "targetCapacity": target}},
        )

    results = _run_concurrent([lambda: _update(50), lambda: _update(75)], timeout_s=60)
    # ECS accepts both racing updates; each response reflects its own value.
    for target, r in zip((50, 75), results, strict=True):
        assert not isinstance(r, BaseException), (
            f"expected the racing update to targetCapacity {target} to be accepted, got "
            f"{_concurrent_error_codes([r])[0]}: {r}"
        )
        cp = r["capacityProvider"]
        assert cp["autoScalingGroupProvider"]["managedScaling"]["targetCapacity"] == target, (
            f"expected the response to reflect targetCapacity {target}, got {cp}"
        )

    final = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0],
        lambda cp: cp.get("updateStatus") in (None, "UPDATE_COMPLETE", "UPDATE_FAILED"),
        timeout_s=90,
        interval_s=3,
        description="the capacity provider's update settles to a terminal (non-in-progress) state",
    )
    assert final.get("updateStatus") == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE, got {final}"
    final_target = final.get("autoScalingGroupProvider", {}).get("managedScaling", {}).get(
        "targetCapacity"
    )
    assert final_target in (50, 75), (
        f"expected the settled targetCapacity to cleanly match ONE of the two racing values "
        f"(50 or 75), got {final_target} (a value outside both would indicate torn/corrupted state)"
    )


def _network_zone_subnets(ctx, zones) -> str:
    """The shared network's subnets in `zones`, comma-separated for VPCZoneIdentifier."""
    by_zone = ctx.network().subnets
    missing = [z for z in zones if z not in by_zone]
    if missing:
        raise AssertionError(f"the run's shared network has no subnet in {missing}")
    return ",".join(by_zone[z] for z in zones)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
