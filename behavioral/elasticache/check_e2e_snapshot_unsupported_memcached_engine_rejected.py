"""e2e-snapshot-unsupported-memcached-engine-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-snapshot-unsupported-memcached-engine-rejected"
GROUP = "state-machine"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSnapshot against a Memcached cluster (an engine that never supports backups) is rejected
    with SnapshotFeatureNotSupportedFault and leaves no snapshot object behind; a Redis cluster in the
    same file still snapshots successfully, proving the rejection is engine-specific, not blanket."""
    ec = ctx.client("elasticache")
    vpc_id, subnet_ids = _default_vpc_subnets(ctx)
    sg_id = _create_test_security_group(ctx, vpc_id)
    subnet_group = ctx.unique_name("sim2real-negsnap-sng-")
    memcached_id = ctx.unique_name("sim2real-mc-")
    redis_id = ctx.unique_name("sim2real-rd-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=subnet_group, CacheSubnetGroupDescription="sim2real test", SubnetIds=subnet_ids
    )
    # Runs after both cluster deletes (LIFO): the subnet group stays in use until every
    # cluster in it is gone, so wait for both before deleting it.
    ctx.on_cleanup(lambda: _delete_subnet_group_after_clusters(ctx, subnet_group, [memcached_id, redis_id]))

    ec.create_cache_cluster(
        CacheClusterId=memcached_id,
        Engine="memcached",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
        SecurityGroupIds=[sg_id],
    )
    ctx.on_cleanup(lambda: _delete_cluster_if_present(ctx, memcached_id))
    _wait_cluster_available(ctx, memcached_id, timeout_s=_budget_s(ctx, 1200.0), interval_s=2.0)

    bad_snapshot_name = ctx.unique_name("sim2real-mc-snap-")
    code, message = _error(lambda: ec.create_snapshot(SnapshotName=bad_snapshot_name, CacheClusterId=memcached_id))
    assert code == "SnapshotFeatureNotSupportedFault", code
    assert message == "The engine type of this cluster does not support snapshotting.", (
        f"unexpected SnapshotFeatureNotSupportedFault message: {message!r}"
    )
    # DescribeSnapshots answers an unknown SnapshotName with an empty list, not SnapshotNotFoundFault
    # (that fault is for DeleteSnapshot/CopySnapshot on a named snapshot).
    absent_snapshots = ec.describe_snapshots(SnapshotName=bad_snapshot_name)["Snapshots"]
    assert absent_snapshots == [], f"rejected snapshot must leave no object behind: {absent_snapshots!r}"

    ec.create_cache_cluster(
        CacheClusterId=redis_id,
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
        SecurityGroupIds=[sg_id],
    )
    ctx.on_cleanup(lambda: _delete_cluster_if_present(ctx, redis_id))
    _wait_cluster_available(ctx, redis_id, timeout_s=_budget_s(ctx, 1200.0), interval_s=2.0)

    good_snapshot_name = ctx.unique_name("sim2real-rd-snap-")
    ec.create_snapshot(SnapshotName=good_snapshot_name, CacheClusterId=redis_id)
    ctx.on_cleanup(lambda: _delete_snapshot_if_present(ctx, good_snapshot_name))
    status = _wait_snapshot_available(
        ctx, good_snapshot_name, timeout_s=_budget_s(ctx, 1200.0), interval_s=2.0
    )
    assert status == "available", status


# The wire code is "CacheClusterNotFound"; the model's shape name carries the "Fault" suffix.
_CLUSTER_NOT_FOUND = {"CacheClusterNotFound", "CacheClusterNotFoundFault"}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _default_vpc_subnets(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to place the ElastiCache clusters in")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available for a cache subnet group")
    return vpc_id, [s["SubnetId"] for s in subnets[:3]]


def _create_test_security_group(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ec-sg-")
    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real elasticache behavioral test",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_released(ec2, sg_id))
    return sg_id


def _wait_cluster_available(ctx, cluster_id: str, timeout_s: float = 1200.0, interval_s: float = 15.0) -> str:
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    last_status = "unknown"
    while time.monotonic() < deadline:
        desc = ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0]
        last_status = desc["CacheClusterStatus"]
        if last_status == "available":
            return last_status
        if last_status in ("create-failed", "restore-failed"):
            raise AssertionError(f"cache cluster {cluster_id} entered terminal failure state {last_status}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cache cluster {cluster_id} available: the run budget ended first; not graded")
    raise AssertionError(f"cache cluster {cluster_id} did not become available within {timeout_s}s (last={last_status})")


def _wait_snapshot_available(ctx, snapshot_name: str, timeout_s: float = 1200.0, interval_s: float = 15.0) -> str:
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    last_status = "unknown"
    while time.monotonic() < deadline:
        desc = ec.describe_snapshots(SnapshotName=snapshot_name)["Snapshots"][0]
        last_status = desc["SnapshotStatus"]
        if last_status == "available":
            return last_status
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"snapshot {snapshot_name} available: the run budget ended first; not graded")
    raise AssertionError(f"snapshot {snapshot_name} did not become available within {timeout_s}s (last={last_status})")


def _delete_cluster_if_present(ctx, cluster_id: str) -> None:
    """Delete the cluster, retrying while it is not yet in a deletable state."""
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + 1200.0
    while True:
        try:
            ec.delete_cache_cluster(CacheClusterId=cluster_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in _CLUSTER_NOT_FOUND:
                return
            if code != "InvalidCacheClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_cluster_gone(ec, cluster_id: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ec.describe_cache_clusters(CacheClusterId=cluster_id)
        except ClientError as e:
            if e.response["Error"]["Code"] in _CLUSTER_NOT_FOUND:
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cache cluster {cluster_id} was not deleted within {timeout_s}s")


def _delete_subnet_group_after_clusters(ctx, subnet_group: str, cluster_ids: list[str]) -> None:
    ec = ctx.client("elasticache")
    for cluster_id in cluster_ids:
        _wait_cluster_gone(ec, cluster_id)
    ec.delete_cache_subnet_group(CacheSubnetGroupName=subnet_group)


def _delete_security_group_when_released(ec2, sg_id: str, timeout_s: float = 180.0, interval_s: float = 2.0) -> None:
    """The deleted clusters' network interfaces release the group a little after the clusters
    disappear, so a DependencyViolation is retried within a bounded window."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_snapshot_if_present(ctx, snapshot_name: str) -> None:
    ec = ctx.client("elasticache")
    try:
        ec.delete_snapshot(SnapshotName=snapshot_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "SnapshotNotFoundFault":
            raise


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises.
    An unexpected SUCCESS raises, so an emulator accepting a call real AWS refuses is reported
    as such rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
