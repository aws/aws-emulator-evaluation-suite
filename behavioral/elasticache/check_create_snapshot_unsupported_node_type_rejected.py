"""create-snapshot-unsupported-node-type-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-snapshot-unsupported-node-type-rejected"
GROUP = "error-semantics"
SERVICES = ["elasticache"]

_VPC_CIDR = "10.229.0.0/16"
_SUBNET_CIDR = "10.229.1.0/24"

_RESOURCE_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": CHECK},
]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSnapshot against a Memcached cluster (an engine that never supports
    backups, regardless of node type) is rejected with SnapshotFeatureNotSupportedFault,
    and no snapshot is ever created for it."""
    ec = ctx.client("elasticache")
    subnet_group = _make_cache_subnet_group(ctx, "sim2real-snapnt-")
    memcached_id = ctx.unique_name("sim2real-ecmc-")
    redis_id = ctx.unique_name("sim2real-ecrd-")

    ec.create_cache_cluster(
        CacheClusterId=memcached_id,
        Engine="memcached",
        NumCacheNodes=1,
        CacheNodeType="cache.t3.micro",
        CacheSubnetGroupName=subnet_group,
        Tags=_RESOURCE_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_cache_cluster(ctx, memcached_id))

    ec.create_cache_cluster(
        CacheClusterId=redis_id,
        Engine="redis",
        NumCacheNodes=1,
        CacheNodeType="cache.t3.micro",
        CacheSubnetGroupName=subnet_group,
        Tags=_RESOURCE_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_cache_cluster(ctx, redis_id))

    _wait_for_cache_cluster_status(ctx, memcached_id, {"available"}, timeout_s=900)
    _wait_for_cache_cluster_status(ctx, redis_id, {"available"}, timeout_s=900)

    bad_snapshot = ctx.unique_name("sim2real-snapbad-")

    def _snapshot_memcached():
        ec.create_snapshot(CacheClusterId=memcached_id, SnapshotName=bad_snapshot)

    code, message = _error(_snapshot_memcached)
    assert code == "SnapshotFeatureNotSupportedFault", f"expected SnapshotFeatureNotSupportedFault, got {code}"
    expected = "The engine type of this cluster does not support snapshotting."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: DescribeSnapshots filters by name rather than erroring on a miss, so a
    # rejected snapshot must show up as an empty list, not a not-found fault (measured on real
    # AWS: a nonexistent SnapshotName returns 200 with Snapshots=[]).
    found = ec.describe_snapshots(SnapshotName=bad_snapshot)["Snapshots"]
    assert found == [], f"expected no snapshot named {bad_snapshot!r}, found {found!r}"

    # positive control: the same operation against a Redis cluster succeeds
    good_snapshot = ctx.unique_name("sim2real-snapok-")
    ec.create_snapshot(CacheClusterId=redis_id, SnapshotName=good_snapshot, Tags=_RESOURCE_TAGS)
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, good_snapshot))
    status = _wait_for_snapshot_status(ctx, good_snapshot, {"available"}, timeout_s=900)
    assert status == "available", f"positive-control snapshot never became available: {status}"


# ===== helpers =====

def _error(fn):
    """Call fn(); return the botocore Error (Code, Message). A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_for_cache_cluster_status(ctx, cluster_id, target_statuses, timeout_s=900.0, interval_s=15.0):
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = ec.describe_cache_clusters(CacheClusterId=cluster_id)
        clusters = resp.get("CacheClusters", [])
        if clusters:
            status = clusters[0]["CacheClusterStatus"]
            if status in target_statuses:
                return status
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} never reached {target_statuses}, last status={status}")


def _wait_for_snapshot_status(ctx, snapshot_name, target_statuses, timeout_s=900.0, interval_s=15.0):
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = ec.describe_snapshots(SnapshotName=snapshot_name)
        snapshots = resp.get("Snapshots", [])
        if snapshots:
            status = snapshots[0]["SnapshotStatus"]
            if status in target_statuses:
                return status
        time.sleep(interval_s)
    raise AssertionError(f"snapshot {snapshot_name} never reached {target_statuses}, last status={status}")


def _delete_cache_cluster(ctx, cluster_id):
    """Delete the cluster and wait until it is gone, so the subnet group can go after it.

    A cluster still creating is retried; both clusters fit the 1800 s cleanup budget."""
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + 840
    while True:
        try:
            ec.delete_cache_cluster(CacheClusterId=cluster_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "CacheClusterNotFound":
                return
            if code != "InvalidCacheClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            ec.describe_cache_clusters(CacheClusterId=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "CacheClusterNotFound":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"cache cluster {cluster_id} was not deleted within 840 s")


def _delete_snapshot(ctx, snapshot_name):
    ec = ctx.client("elasticache")
    try:
        _wait_for_snapshot_status(ctx, snapshot_name, {"available"}, timeout_s=900)
    except AssertionError:
        pass
    try:
        ec.delete_snapshot(SnapshotName=snapshot_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "SnapshotNotFoundFault":
            raise


def _delete_ec2_quietly(fn, not_found_codes):
    try:
        fn()
    except ClientError as exc:
        if (exc.response.get("Error", {}).get("Code") or "") not in not_found_codes:
            raise


def _delete_subnet_group_quietly(ec, name):
    try:
        ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "CacheSubnetGroupNotFoundFault":
            raise


def _make_cache_subnet_group(ctx, prefix):
    """Create a throwaway VPC, one subnet and a cache subnet group over it.

    The cluster never lands in an ambient default VPC. Cleanups run last-in first-out: the
    cluster (registered after this returns) is gone before the group, subnet and VPC go.
    """
    ec2 = ctx.client("ec2")
    ec = ctx.client("elasticache")
    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name(prefix + "vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _delete_ec2_quietly(
            lambda: ec2.delete_vpc(VpcId=vpc_id), ("InvalidVpcID.NotFound",)
        )
    )
    az = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=_SUBNET_CIDR,
        AvailabilityZone=az,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name(prefix + "subnet-")}],
        }],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_ec2_quietly(
            lambda: ec2.delete_subnet(SubnetId=subnet_id), ("InvalidSubnetID.NotFound",)
        )
    )
    group_name = ctx.unique_name(prefix + "sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=group_name,
        CacheSubnetGroupDescription="sim2real throwaway subnet group",
        SubnetIds=[subnet_id],
    )
    ctx.on_cleanup(lambda: _delete_subnet_group_quietly(ec, group_name))
    return group_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
