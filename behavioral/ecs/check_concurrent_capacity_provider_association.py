"""concurrent-capacity-provider-association."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-capacity-provider-association"
GROUP = 'concurrency'
SERVICES = ['ecs']

# Transient codes either racer can hit while the other's mutation settles (ECS serializes
# these) or under throttling; retried, bounded, rather than treated as a lost update.
_TRANSIENT_CODES = {
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestLimitExceeded",
    "ServerException",
    "InternalServerError",
    "InternalFailure",
    "ServiceUnavailable",
    "ServiceUnavailableException",
    "UpdateInProgressException",
    "ConflictException",
}


def _retry_transient(fn, *, timeout_s=90, interval_s=3):
    """Call fn, retrying only on transient/throttle/contention ClientError codes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_CODES or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
    ctx.on_cleanup(lambda: _retry_busy(lambda: ecs.delete_capacity_provider(capacityProvider=cp_name)))
    return cp_name


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutClusterCapacityProviders racing UpdateCapacityProvider on the same provider: each racer
    either fails with a contention code or takes effect (provider attached, targetCapacity settled
    to the new value), never a half-applied combination."""
    ecs = ctx.client("ecs")
    cp_name = _create_shell_capacity_provider(ctx, ecs)
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: _retry_busy(lambda: ecs.delete_cluster(cluster=name)))
    ctx.on_cleanup(
        lambda: _retry_busy(
            lambda: ecs.put_cluster_capacity_providers(
                cluster=name, capacityProviders=[], defaultCapacityProviderStrategy=[]
            )
        )
    )

    def _attach():
        return _retry_transient(
            lambda: ecs.put_cluster_capacity_providers(
                cluster=name,
                capacityProviders=[cp_name],
                defaultCapacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}],
            )
        )

    def _update_scaling():
        return _retry_transient(
            lambda: ecs.update_capacity_provider(
                name=cp_name,
                autoScalingGroupProvider={"managedScaling": {"status": "ENABLED", "targetCapacity": 70}},
            )
        )

    # Must exceed each racer's own 90 s retry deadline, or a racer still retrying through
    # contention would be cancelled and misreported as lost.
    results = _run_concurrent([_attach, _update_scaling], timeout_s=100)
    # ECS applies both racers: neither is refused.
    for label, r in zip(("PutClusterCapacityProviders", "UpdateCapacityProvider"), results, strict=True):
        assert not isinstance(r, BaseException), (
            f"expected the racing {label} to be accepted, got {_concurrent_error_codes([r])[0]}: {r}"
        )

    final_cluster = _poll_until(
        lambda: ecs.describe_clusters(clusters=[name])["clusters"][0],
        lambda c: cp_name in c.get("capacityProviders", []),
        timeout_s=60,
        interval_s=3,
        description="the capacity provider becomes attached to the cluster",
    )
    assert final_cluster["capacityProviders"] == [cp_name], (
        f"expected exactly {cp_name} attached to the cluster, got {final_cluster['capacityProviders']}"
    )

    final_cp = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0],
        lambda cp: cp.get("updateStatus") in (None, "UPDATE_COMPLETE", "UPDATE_FAILED"),
        timeout_s=90,
        interval_s=3,
        description="the capacity provider's update settles to a terminal (non-in-progress) state",
    )
    assert final_cp.get("updateStatus") == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE, got {final_cp}"
    final_scaling = final_cp["autoScalingGroupProvider"]["managedScaling"]
    assert final_scaling["status"] == "ENABLED" and final_scaling["targetCapacity"] == 70, (
        f"expected managedScaling ENABLED at targetCapacity 70 (the racing update's value), got "
        f"{final_scaling} -- anything else would indicate a lost/half-applied update"
    )

def _retry_busy(fn, timeout_s=120, interval_s=5):
    """Teardown: retry fn while the cluster answers UpdateInProgressException (a
    capacity-provider change still settling); any other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "UpdateInProgressException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
