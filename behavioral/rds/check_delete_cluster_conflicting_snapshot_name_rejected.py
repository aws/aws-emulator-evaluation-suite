"""delete-cluster-conflicting-snapshot-name-rejected."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

import botocore.exceptions

from behavioral_harness import tags

CHECK = "delete-cluster-conflicting-snapshot-name-rejected"
GROUP = "negative-classes"
SERVICES = ["rds"]

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-delconflict"},
]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """DeleteDBCluster with a FinalDBSnapshotIdentifier naming an existing manual snapshot fails with
    DBClusterSnapshotAlreadyExistsFault, keeping the cluster and that snapshot, while deleting with a new
    final snapshot name succeeds."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-delconflict-")
    password = _rand_password()
    cluster_deleted = False

    def _cleanup_cluster():
        if cluster_deleted:
            return
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
        except botocore.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] != "DBClusterNotFoundFault":
                raise

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 1},
        DeletionProtection=False,
        Tags=_MANAGED_TAGS,
        CopyTagsToSnapshot=True,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(_cleanup_cluster)
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=900)

    pre_existing_snapshot = ctx.unique_name("sim2real-snap-")
    rds.create_db_cluster_snapshot(
        DBClusterSnapshotIdentifier=pre_existing_snapshot, DBClusterIdentifier=cluster_id
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=pre_existing_snapshot)
    )
    original = _wait_snapshot_status(ctx, pre_existing_snapshot, "available", timeout_s=300)
    original_create_time = original["SnapshotCreateTime"]

    code, message = _error_code(
        lambda: rds.delete_db_cluster(
            DBClusterIdentifier=cluster_id,
            SkipFinalSnapshot=False,
            FinalDBSnapshotIdentifier=pre_existing_snapshot,
        )
    )
    assert code == "DBClusterSnapshotAlreadyExistsFault", f"unexpected error code {code!r}"
    assert message == (
        "Cannot create the cluster snapshot because one with the identifier "
        f"{pre_existing_snapshot} already exists."
    ), f"unexpected message {message!r}"

    # Effect absent: the cluster still exists, and the pre-existing snapshot was not overwritten.
    still_there = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert still_there["DBClusterIdentifier"] == cluster_id
    snaps = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=pre_existing_snapshot)[
        "DBClusterSnapshots"
    ]
    assert len(snaps) == 1
    assert snaps[0]["SnapshotCreateTime"] == original_create_time, (
        "the pre-existing snapshot's creation time changed -- it was overwritten"
    )

    # Positive control (same file): deleting with a genuinely NEW final snapshot name succeeds.
    new_snapshot_id = ctx.unique_name("sim2real-finalsnap-")
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=300)
    _retry_delete_with_snapshot(ctx, cluster_id, new_snapshot_id, timeout_s=300)
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=new_snapshot_id)
    )
    _wait_cluster_gone(ctx, cluster_id, timeout_s=900)
    cluster_deleted = True
    _wait_snapshot_status(ctx, new_snapshot_id, "available", timeout_s=300)


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - classify below
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=900, poll_s=20) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"cluster {cluster_id} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _wait_cluster_gone(ctx, cluster_id, timeout_s=900, poll_s=20) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except rds.exceptions.DBClusterNotFoundFault:
            return
        time.sleep(poll_s)
    raise AssertionError(f"cluster {cluster_id} was still visible after {timeout_s}s")


def _retry_delete_with_snapshot(ctx, cluster_id, snapshot_id, timeout_s=300, poll_s=15) -> None:
    """DeleteDBCluster with FinalDBSnapshotIdentifier transiently rejects with
    InvalidDBClusterStateFault ("Can't create a snapshot because the database cluster is not
    in available state") for a short window after a prior snapshot/delete attempt on the same
    cluster; bounded-retry, not one shot."""
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            rds.delete_db_cluster(
                DBClusterIdentifier=cluster_id,
                SkipFinalSnapshot=False,
                FinalDBSnapshotIdentifier=snapshot_id,
            )
            return
        except botocore.exceptions.ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidDBClusterStateFault":
                raise
            last_exc = exc
            time.sleep(poll_s)
    raise AssertionError(f"DeleteDBCluster never became valid within {timeout_s}s: {last_exc}")


def _wait_snapshot_status(ctx, snapshot_id, target_status, timeout_s=300, poll_s=15) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshot_id)[
            "DBClusterSnapshots"
        ][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"snapshot {snapshot_id} never reached {target_status!r}, "
        f"last status {last and last['Status']!r}"
    )


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
