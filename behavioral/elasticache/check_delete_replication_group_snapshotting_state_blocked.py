"""delete-replication-group-snapshotting-state-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-replication-group-snapshotting-state-blocked"
GROUP = "overly-permissive"
SERVICES = ["elasticache"]

_VPC_CIDR = "10.234.0.0/16"
_SUBNET_CIDR = "10.234.1.0/24"
# budget.cleanup_timeout for behavioral/elasticache, one deadline shared by every teardown of a run.
_TEARDOWN_S = 1800.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteReplicationGroup while a manual snapshot of its node is in progress is refused with
    InvalidReplicationGroupState "Cache cluster <id> is not in a valid state to be deleted." and the group stays;
    once the snapshot is available the same delete succeeds and the group goes away."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    ec = ctx.client("elasticache")
    subnet_group_name = _make_cache_subnet_group(ctx, "sim2real-ecrg-", teardown_deadline)
    rg_id = ctx.unique_name("sim2real-ecrg-")
    snap_name = ctx.unique_name("sim2real-ecsnap-")

    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real behavioral check: delete-while-snapshotting",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        CacheSubnetGroupName=subnet_group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_replication_group_and_wait_gone(ec, rg_id, teardown_deadline))

    _wait_replication_group_available(ec, rg_id, timeout_s=1500.0)
    rg = _replication_group(ec, rg_id)
    # Cluster-mode-disabled replication groups cannot be snapshotted via
    # ReplicationGroupId (CreateSnapshot requires the member CacheClusterId
    # instead: "Cannot snapshot a replication group with cluster-mode disabled.
    # Please specify a cache cluster instead."). Use the RG's sole member cluster.
    member_cluster_id = rg["MemberClusters"][0]

    ec.create_snapshot(
        CacheClusterId=member_cluster_id,
        SnapshotName=snap_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_snapshot_and_wait_gone(ec, snap_name, teardown_deadline))

    # The check's own CreateSnapshot holds the in-progress window; the group itself stays
    # 'available', so the refusal names the member cluster the snapshot is running on.
    _poll_until(
        lambda: _snapshot_status(ec, snap_name),
        lambda status: status is not None,
        timeout_s=120.0,
        interval_s=3.0,
    )

    _assert_error(
        lambda: ec.delete_replication_group(ReplicationGroupId=rg_id),
        ("InvalidReplicationGroupState", f"Cache cluster {member_cluster_id} is not in a valid state to be deleted."),
    )

    # Effect absent: the replication group must still exist.
    still_there = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
    assert len(still_there) == 1, "replication group disappeared despite blocked delete"

    # Positive control: once the snapshot completes, delete succeeds.
    _poll_until(
        lambda: _snapshot_status(ec, snap_name),
        lambda status: status == "available",
        timeout_s=900.0,
        interval_s=15.0,
    )
    _wait_replication_group_available(ec, rg_id, timeout_s=300.0)
    ec.delete_replication_group(ReplicationGroupId=rg_id)
    deleted_ok = _replication_group_status(ec, rg_id)
    assert deleted_ok in ("deleting", None), f"delete did not take effect, status={deleted_ok}"
    _poll_until(
        lambda: _replication_group_status(ec, rg_id),
        lambda status: status is None,
        timeout_s=1500.0,
        interval_s=15.0,
    )


def _error(fn):
    """Call fn(); return the botocore Error (Code, Message). A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _assert_error(fn, expected):
    """Assert fn() fails with exactly the (code, message) pair `expected`."""
    code, message = _error(fn)
    assert code == expected[0], f"expected {expected[0]}, got {code}"
    assert message == expected[1], f"expected message {expected[1]!r}, got {message!r}"


def _teardown_deadline_of(teardown_deadline: dict) -> float:
    return teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_S - 120.0)


def _delete_replication_group_and_wait_gone(ec, rg_id, teardown_deadline):
    """Delete the group once it is deletable (tolerating one already deleting or gone) and wait
    until it is gone, so the subnet group registered before it can be deleted after it."""
    deadline = _teardown_deadline_of(teardown_deadline)
    while time.monotonic() < deadline:
        status = _replication_group_status(ec, rg_id)
        if status is None:
            return
        if status == "available":
            try:
                ec.delete_replication_group(ReplicationGroupId=rg_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ReplicationGroupNotFoundFault", "InvalidReplicationGroupState"
                ):
                    raise
        time.sleep(15)
    raise AssertionError(f"replication group {rg_id} still present at the teardown deadline")


def _teardown(teardown_deadline, fn, gone, retry):
    """Done when fn succeeds or answers a `gone` code; retry the `retry` codes every 2 s to the
    shared teardown deadline (ElastiCache releases a subnet group and its ENIs after the group
    is gone), and raise everything else."""
    deadline = _teardown_deadline_of(teardown_deadline)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code") or ""
            if code in gone:
                return
            if code not in retry or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _make_cache_subnet_group(ctx, prefix, teardown_deadline):
    """Create a throwaway VPC, one subnet and a cache subnet group over it.

    The group never lands in an ambient default VPC. Cleanups run last-in first-out: the
    replication group (registered after this returns) is gone before the subnet group, subnet
    and VPC go.
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
    ctx.on_cleanup(lambda: _teardown(
        teardown_deadline, lambda: ec2.delete_vpc(VpcId=vpc_id),
        gone=("InvalidVpcID.NotFound",), retry=("DependencyViolation",),
    ))
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
    ctx.on_cleanup(lambda: _teardown(
        teardown_deadline, lambda: ec2.delete_subnet(SubnetId=subnet_id),
        gone=("InvalidSubnetID.NotFound",), retry=("DependencyViolation",),
    ))
    name = ctx.unique_name(prefix + "sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real behavioral",
        SubnetIds=[subnet_id],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown(
        teardown_deadline, lambda: ec.delete_cache_subnet_group(CacheSubnetGroupName=name),
        gone=("CacheSubnetGroupNotFoundFault",), retry=("CacheSubnetGroupInUse",),
    ))
    return name


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _replication_group_status(ec, rg_id):
    try:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ReplicationGroupNotFoundFault":
            return None
        raise
    if not groups:
        return None
    return groups[0]["Status"]


def _replication_group(ec, rg_id):
    groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
    if not groups:
        raise AssertionError(f"replication group {rg_id!r} disappeared unexpectedly")
    return groups[0]


def _wait_replication_group_available(ec, rg_id, timeout_s=900.0):
    return _poll_until(
        lambda: _replication_group_status(ec, rg_id),
        lambda status: status == "available",
        timeout_s=timeout_s,
        interval_s=15.0,
    )


def _snapshot_status(ec, snap_name):
    try:
        snaps = ec.describe_snapshots(SnapshotName=snap_name)["Snapshots"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "SnapshotNotFoundFault":
            return None
        raise
    if not snaps:
        return None
    return snaps[0]["SnapshotStatus"]


# Snapshot states in which DeleteSnapshot is refused with InvalidSnapshotState.
_SNAPSHOT_BUSY = ("creating", "restoring", "copying")


def _delete_snapshot_and_wait_gone(ec, snap_name, teardown_deadline):
    """Delete the snapshot once it leaves a busy state and wait every 2 s until it is gone, to the
    shared teardown deadline; any other failure, or the deadline passing, raises."""
    deadline = _teardown_deadline_of(teardown_deadline)
    while True:
        status = _snapshot_status(ec, snap_name)
        if status is None:
            return
        if status not in _SNAPSHOT_BUSY and status != "deleting":
            try:
                ec.delete_snapshot(SnapshotName=snap_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("SnapshotNotFoundFault", "InvalidSnapshotState"):
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"snapshot {snap_name} still {status!r} at the teardown deadline")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
