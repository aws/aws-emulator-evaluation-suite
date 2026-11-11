"""snapshot-delete-lifecycle-removes-resource."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "snapshot-delete-lifecycle-removes-resource"
GROUP = "state"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASSWORD = "Sim2RealPassw0rd123"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteClusterSnapshot on an ACTIVE manual snapshot drives ACTIVE -> DELETING ->
    removed: afterwards GetClusterSnapshot and ListClusterSnapshots both stop reflecting
    the snapshot, while the source cluster is untouched."""
    client = ctx.client("docdb-elastic")
    cluster_name = ctx.unique_name("sim2real-elastic-snapdel-")

    cluster_resp = client.create_cluster(
        clusterName=cluster_name,
        authType="PLAIN_TEXT",
        adminUserName=_ADMIN_USER,
        adminUserPassword=_ADMIN_PASSWORD,
        shardCapacity=2,
        shardCount=1,
        tags={"sim2real-check": CHECK},
    )
    cluster_arn = cluster_resp["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_cluster(client, cluster_arn))
    _wait_for_cluster_status(client, cluster_arn, {"ACTIVE"})

    snapshot_name = ctx.unique_name("sim2real-elastic-snap-")
    snapshot_arn = client.create_cluster_snapshot(
        clusterArn=cluster_arn, snapshotName=snapshot_name, tags={"sim2real-check": CHECK}
    )["snapshot"]["snapshotArn"]
    _wait_for_snapshot_status(client, snapshot_arn, {"ACTIVE"})

    client.delete_cluster_snapshot(snapshotArn=snapshot_arn)
    _wait_for_snapshot_absent(client, snapshot_arn)

    names = [
        s["snapshotName"]
        for s in client.list_cluster_snapshots(maxResults=100).get("snapshots", [])
    ]
    assert snapshot_name.lower() not in names, "deleted snapshot still appears in ListClusterSnapshots"

    # an operation that demonstrably worked on this snapshot earlier (delete) now fails
    # with the specific not-found error on the same dead id
    try:
        client.delete_cluster_snapshot(snapshotArn=snapshot_arn)
        raise AssertionError("deleting an already-deleted snapshot unexpectedly succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException deleting a dead snapshot, got {code!r}"
        )
        message = e.response["Error"].get("Message")
        assert message == "Unable to find the snapshot", (
            f"expected message 'Unable to find the snapshot', got {message!r}"
        )

    # the source cluster is unaffected by the snapshot deletion
    cluster_after = client.get_cluster(clusterArn=cluster_arn)["cluster"]
    assert cluster_after["status"] == "ACTIVE", (
        f"source cluster status changed after snapshot delete: {cluster_after['status']!r}"
    )


def _wait_for_cluster_status(client, cluster_arn, target_statuses, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cluster = client.get_cluster(clusterArn=cluster_arn)["cluster"]
        last_status = cluster["status"]
        if last_status in target_statuses:
            return cluster
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last status={last_status}")


def _wait_for_snapshot_status(client, snapshot_arn, target_statuses, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        snapshot = client.get_cluster_snapshot(snapshotArn=snapshot_arn)["snapshot"]
        last_status = snapshot["status"]
        if last_status in target_statuses:
            return snapshot
        time.sleep(interval_s)
    raise AssertionError(f"snapshot never reached {target_statuses}, last status={last_status}")


def _wait_for_snapshot_absent(client, snapshot_arn, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            client.get_cluster_snapshot(snapshotArn=snapshot_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError("snapshot was not deleted within timeout")


def _best_effort_delete_cluster(client, cluster_arn):
    try:
        client.delete_cluster(clusterArn=cluster_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
