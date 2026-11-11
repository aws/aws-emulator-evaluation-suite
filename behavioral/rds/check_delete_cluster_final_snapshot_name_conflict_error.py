"""delete-cluster-final-snapshot-name-conflict-error."""
from __future__ import annotations

import time
from typing import Any, Callable

import botocore.exceptions

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-cluster-final-snapshot-name-conflict-error"
GROUP = "error-semantics"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBCluster with a FinalDBSnapshotIdentifier naming an existing snapshot fails with
    DBClusterSnapshotAlreadyExistsFault, leaving cluster and snapshot untouched; the same delete
    with a new final snapshot name succeeds."""
    cluster_id = ctx.unique_name("sim2real-clus-")
    snap_id = ctx.unique_name("sim2real-snap-")
    rds = ctx.client("rds")

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="simadmin",
        MasterUserPassword="Sim2Real!Pwd01",
        DatabaseName="simdb",
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_id))
    _wait_for_cluster_status(ctx, cluster_id, "available", timeout_s=900)

    rds.create_db_cluster_snapshot(
        DBClusterSnapshotIdentifier=snap_id,
        DBClusterIdentifier=cluster_id,
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_cluster_snapshot(ctx, snap_id))
    original = _wait_for_cluster_snapshot_status(ctx, snap_id, "available", timeout_s=600)
    original_create_time = original["SnapshotCreateTime"]
    # The cluster itself transiently reports "backing-up" while the manual snapshot is being
    # taken; wait for it to settle back to "available" before probing state below.
    _wait_for_cluster_status(ctx, cluster_id, "available", timeout_s=600)

    code, message = _error_code(
        lambda: rds.delete_db_cluster(
            DBClusterIdentifier=cluster_id,
            SkipFinalSnapshot=False,
            FinalDBSnapshotIdentifier=snap_id,
        )
    )
    assert code == "DBClusterSnapshotAlreadyExistsFault", code
    assert message == (
        f"Cannot create the cluster snapshot because one with the identifier {snap_id} already exists."
    ), message

    # Effect absent: the cluster is not deleting and the existing snapshot is not overwritten.
    desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert desc["Status"] == "available", desc["Status"]
    snaps = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snap_id)[
        "DBClusterSnapshots"
    ]
    assert len(snaps) == 1, snaps
    assert snaps[0]["SnapshotCreateTime"] == original_create_time, (
        f"snapshot {snap_id} creation time changed from {original_create_time} to "
        f"{snaps[0]['SnapshotCreateTime']} -- it was overwritten by the rejected call"
    )

    # Control: the same delete with a new final snapshot name (not skipping it) succeeds.
    new_snap_id = ctx.unique_name("sim2real-finalsnap-")
    _delete_cluster_with_final_snapshot_retrying_transient_state(
        ctx, cluster_id, new_snap_id, timeout_s=300
    )
    ctx.on_cleanup(lambda: _safe_delete_cluster_snapshot(ctx, new_snap_id))
    _wait_for_cluster_gone_or_deleting(ctx, cluster_id, timeout_s=900)
    _wait_for_cluster_snapshot_status(ctx, new_snap_id, "available", timeout_s=600)


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its error (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float = 15.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _wait_for_cluster_status(ctx, cluster_id: str, status: str, *, timeout_s: float) -> None:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]["Status"]

    _poll_until(probe, lambda s: s == status, timeout_s=timeout_s)


def _wait_for_cluster_gone_or_deleting(ctx, cluster_id: str, *, timeout_s: float) -> None:
    from botocore.exceptions import ClientError

    rds = ctx.client("rds")

    def probe():
        try:
            return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return "gone"
            raise

    _poll_until(probe, lambda s: s in ("gone", "deleting"), timeout_s=timeout_s)


def _wait_for_cluster_snapshot_status(ctx, snap_id: str, status: str, *, timeout_s: float) -> dict:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snap_id)[
            "DBClusterSnapshots"
        ][0]

    return _poll_until(probe, lambda snap: snap["Status"] == status, timeout_s=timeout_s)


def _delete_cluster_with_final_snapshot_retrying_transient_state(
    ctx, cluster_id: str, snap_id: str, *, timeout_s: float, interval_s: float = 15.0
) -> None:
    """DeleteDBCluster with a final snapshot, retrying InvalidDBClusterStateFault (bounded).

    The call is briefly rejected that way after a preceding snapshot on the same cluster."""
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last_exc: botocore.exceptions.ClientError | None = None
    while time.monotonic() < deadline:
        try:
            rds.delete_db_cluster(
                DBClusterIdentifier=cluster_id,
                SkipFinalSnapshot=False,
                FinalDBSnapshotIdentifier=snap_id,
            )
            return
        except botocore.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidDBClusterStateFault":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"DeleteDBCluster never became valid within {timeout_s}s: {last_exc}")


def _safe_delete_cluster(ctx, cluster_id: str) -> None:
    from botocore.exceptions import ClientError

    rds = ctx.client("rds")
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DBClusterNotFoundFault", "InvalidDBClusterStateFault"):
            raise


def _safe_delete_cluster_snapshot(ctx, snap_id: str) -> None:
    from botocore.exceptions import ClientError

    rds = ctx.client("rds")
    try:
        rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBClusterSnapshotNotFoundFault":
            raise


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
