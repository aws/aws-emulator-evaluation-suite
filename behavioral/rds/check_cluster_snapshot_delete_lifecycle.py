"""cluster-snapshot-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "cluster-snapshot-delete-lifecycle"
GROUP = 'snapshots'
SERVICES = ['rds']

ERR_CLUSTER_SNAPSHOT_NOT_FOUND = "DBClusterSnapshotNotFoundFault"


def _error_detail(fn):
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("the call succeeded; expected a rejection")


def _poll_until(probe, predicate, *, timeout_s=600, interval_s=5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBClusterSnapshot removes a manual cluster snapshot: it is not describable afterwards and a
    second delete fails with DBClusterSnapshotNotFoundFault, as does any unknown identifier."""
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx)
    cluster_id = ctx.unique_name("sim2real-behav-clu-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="admin",
        MasterUserPassword="Sim2Real#Pass99",
        BackupRetentionPeriod=1,
        DBSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rds, cluster_id))
    _poll_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0],
        lambda c: c.get("Status") == "available",
        timeout_s=600,
        interval_s=5,
        description=f"cluster {cluster_id} available",
    )

    snap_id = ctx.unique_name("sim2real-behav-clusnap-")
    rds.create_db_cluster_snapshot(
        DBClusterIdentifier=cluster_id,
        DBClusterSnapshotIdentifier=snap_id,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_snapshot_if_exists(rds, snap_id))

    def probe():
        resp = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snap_id)
        snaps = resp.get("DBClusterSnapshots", [])
        return snaps[0] if snaps else None

    _poll_until(
        probe,
        lambda s: s is not None and s.get("Status") == "available",
        timeout_s=600,
        interval_s=5,
        description=f"cluster snapshot {snap_id} available",
    )

    rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id)
    code, message = _error_detail(
        lambda: rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snap_id)
    )
    assert code == ERR_CLUSTER_SNAPSHOT_NOT_FOUND, f"unexpected error code: {code}"
    expected = f"DBClusterSnapshot not found: {snap_id}"
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    # The dead id itself must reject a further mutation -- not just be absent from reads.
    code_dead, message_dead = _error_detail(
        lambda: rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id)
    )
    assert code_dead == ERR_CLUSTER_SNAPSHOT_NOT_FOUND, (
        f"double-delete of the dead snapshot id: unexpected error code: {code_dead}"
    )
    assert message_dead == expected, (
        f"double-delete of the dead snapshot id: unexpected message: {message_dead!r} "
        f"(expected {expected!r})"
    )

    bogus_snap = ctx.unique_name("sim2real-behav-clusnap-missing-")
    code2, message2 = _error_detail(
        lambda: rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=bogus_snap)
    )
    assert code2 == ERR_CLUSTER_SNAPSHOT_NOT_FOUND, f"unexpected error code: {code2}"
    expected2 = f"DBClusterSnapshot not found: {bogus_snap}"
    assert message2 == expected2, f"unexpected message: {message2!r} (expected {expected2!r})"


def _default_subnet_ids(ctx, count: int = 2) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    ids = sorted({s["SubnetId"] for s in subnets})[:count]
    assert len(ids) >= 2, "need at least 2 subnets to create a DB subnet group"
    return ids


def _delete_snapshot_if_exists(rds, snap_id: str) -> None:
    try:
        rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id)
    except rds.exceptions.DBClusterSnapshotNotFoundFault:
        pass


def _delete_cluster_and_wait(rds, cluster_id: str, timeout_s: float = 900.0) -> None:
    """Delete the cluster and wait until it is gone, so the subnet group teardown after it
    does not race a cluster still in "deleting"."""
    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except rds.exceptions.DBClusterNotFoundFault:
            return
        time.sleep(15)
    raise AssertionError(f"cluster {cluster_id} was not deleted within {timeout_s}s")


def _create_subnet_group(ctx) -> str:
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-clusnap-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=_default_subnet_ids(ctx),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
