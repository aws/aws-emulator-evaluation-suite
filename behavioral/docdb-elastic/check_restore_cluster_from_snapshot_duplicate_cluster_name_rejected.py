"""restore-cluster-from-snapshot-duplicate-cluster-name-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-cluster-from-snapshot-duplicate-cluster-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["docdb-elastic"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreClusterFromSnapshot under an existing cluster's name fails with ValidationException and its
    exact "Invalid cluster name" message and leaves that cluster ACTIVE with its ARN, while a restore under
    an unused name creates a new cluster that reaches ACTIVE."""
    docdb = ctx.client("docdb-elastic")
    source = _create_cluster(ctx)
    source_arn = source["clusterArn"]
    source_name = source["clusterName"]
    # One teardown deletes every cluster and snapshot of the run together, so the deletes overlap.
    clusters, snapshots = [source_arn], []
    ctx.on_cleanup(lambda: _delete_all(docdb, clusters, snapshots, time.monotonic() + _TEARDOWN_S))
    _wait_for_cluster_status(ctx, source_arn, {"ACTIVE"})

    snapshot_arn = docdb.create_cluster_snapshot(
        clusterArn=source_arn,
        snapshotName=ctx.unique_name("sim2real-docdbe-snap-"),
        tags={"sim2real-check": CHECK},
    )["snapshot"]["snapshotArn"]
    snapshots.append(snapshot_arn)
    _wait_for_snapshot_status(ctx, snapshot_arn, {"ACTIVE"})

    code, message = _error_code(
        lambda: docdb.restore_cluster_from_snapshot(
            clusterName=source_name, snapshotArn=snapshot_arn
        )
    )
    # Real AWS validates clusterName uniqueness as part of request validation, not as a
    # state conflict: it answers ValidationException here, not ConflictException.
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "Invalid cluster name: Cluster names are case-insensitive and cannot be the same as name as an "
        f"existing cluster. Cluster name {source_name} is not valid because cluster {source_name} exists."
    )
    assert message == expected, f"unexpected message: {message!r}"

    # Effect absent: the original cluster is unaffected -- same arn, still ACTIVE.
    unchanged = docdb.get_cluster(clusterArn=source_arn)["cluster"]
    assert unchanged["clusterArn"] == source_arn, (
        f"expected the source cluster arn {source_arn!r} unchanged, got {unchanged['clusterArn']!r}"
    )
    assert unchanged["status"] == "ACTIVE", (
        f"expected source cluster status ACTIVE after the rejected restore, got {unchanged['status']!r}"
    )

    # Positive control: restoring under a brand-new name still succeeds.
    restored_name = ctx.unique_name("sim2real-docdbe-restored-")
    restored = docdb.restore_cluster_from_snapshot(
        clusterName=restored_name, snapshotArn=snapshot_arn
    )["cluster"]
    clusters.append(restored["clusterArn"])
    assert restored["clusterArn"] != source_arn, (
        f"expected a distinct cluster arn from the restore, got the source arn {source_arn!r} back"
    )
    active_restored = _wait_for_cluster_status(ctx, restored["clusterArn"], {"ACTIVE"})
    assert active_restored["status"] == "ACTIVE", (
        f"expected restored cluster status ACTIVE, got {active_restored['status']!r}"
    )


# ===== helpers =====
def _admin_password(ctx):
    suffix = re.sub(r"[^A-Za-z0-9]", "", ctx.unique_name("x"))[:12]
    return f"S1mparityPw{suffix}"


def _create_cluster(ctx, **overrides):
    docdb = ctx.client("docdb-elastic")
    params = {
        "clusterName": ctx.unique_name("sim2real-docdbe-"),
        "authType": "PLAIN_TEXT",
        "adminUserName": "sim2realadmin",
        "adminUserPassword": _admin_password(ctx),
        "shardCapacity": 2,
        "shardCount": 1,
        "tags": {"sim2real-check": CHECK},
    }
    params.update(overrides)
    return docdb.create_cluster(**params)["cluster"]


def _error_code(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available and must not be
    reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


_TRANSIENT_STATUSES = {
    "CREATING", "STARTING", "STOPPING", "UPDATING", "DELETING",
    "MERGING", "MODIFYING", "SPLITTING", "COPYING", "MAINTENANCE",
}


def _wait_for_cluster_status(ctx, arn, targets, timeout_s=1800.0, interval_s=15.0):
    docdb = ctx.client("docdb-elastic")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = docdb.get_cluster(clusterArn=arn)["cluster"]
        if last["status"] in targets:
            return last
        if last["status"] not in _TRANSIENT_STATUSES:
            raise AssertionError(
                f"cluster {arn} reached unexpected terminal status {last['status']!r} "
                f"while waiting for {targets}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"cluster {arn} did not reach {targets} within {timeout_s}s "
        f"(last status={last['status'] if last else None})"
    )


def _wait_for_snapshot_status(ctx, arn, targets, timeout_s=900.0, interval_s=10.0):
    docdb = ctx.client("docdb-elastic")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = docdb.get_cluster_snapshot(snapshotArn=arn)["snapshot"]
        if last["status"] in targets:
            return last
        if last["status"] not in {"CREATING", "COPYING", "DELETING"}:
            raise AssertionError(f"snapshot {arn} unexpected status {last['status']!r}")
        time.sleep(interval_s)
    raise AssertionError(
        f"snapshot {arn} did not reach {targets} within {timeout_s}s "
        f"(last status={last['status'] if last else None})"
    )


# Inside the 1800 s docdb-elastic cleanup budget.
_TEARDOWN_S = 1680.0
# DeleteCluster and StartCluster answer ValidationException with these messages while the cluster is in a
# state that refuses them; a STOPPED elastic cluster cannot be deleted until it is started.
_REFUSED_FOR_STATE = (
    "Can't delete the cluster because it is in ",
    "Can't start the cluster as it's currently in state",
    "Can't perform operation on cluster as it's in use",
)


def _refused_for_state(exc):
    err = exc.response["Error"]
    message = err.get("Message") or ""
    return err["Code"] == "ConflictException" or (
        err["Code"] == "ValidationException" and message.startswith(_REFUSED_FOR_STATE)
    )


def _cluster_step(client, arn):
    """One teardown step for a cluster: start it when STOPPED, delete it once it has left any transitional
    status. Returns True when GetCluster answers not-found."""
    try:
        status = client.get_cluster(clusterArn=arn)["cluster"]["status"]
        if status == "STOPPED":
            client.start_cluster(clusterArn=arn)
        elif status not in _TRANSIENT_STATUSES:
            client.delete_cluster(clusterArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        if not _refused_for_state(exc):
            raise
    return False


def _snapshot_step(client, arn):
    """Delete a snapshot; True once it is gone. ConflictException (the snapshot is busy) is retried."""
    try:
        client.delete_cluster_snapshot(snapshotArn=arn)
        return True
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return True
        if code != "ConflictException":
            raise
    return False


def _delete_all(client, clusters, snapshots, deadline):
    """Delete every snapshot and cluster together, polling every 2 s until GetCluster answers not-found for
    each cluster; a busy refusal is retried until ``deadline``. Any other failure, or the deadline passing
    with a resource left, raises."""
    clusters, snapshots = list(clusters), list(snapshots)
    while True:
        snapshots = [arn for arn in snapshots if not _snapshot_step(client, arn)]
        clusters = [arn for arn in clusters if not _cluster_step(client, arn)]
        if not clusters and not snapshots:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"still present at the teardown deadline: clusters {clusters}, snapshots {snapshots}"
            )
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
