"""snapshot-create-lifecycle-reaches-active."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "snapshot-create-lifecycle-reaches-active"
GROUP = "state"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASSWORD = "Sim2RealPassw0rd123"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateClusterSnapshot on an ACTIVE cluster transitions (none) -> CREATING ->
    ACTIVE, the resulting snapshot is always snapshotType MANUAL for a user-invoked
    call, and it references the source cluster's ARN and admin user."""
    client = ctx.client("docdb-elastic")
    cluster_name = ctx.unique_name("sim2real-elastic-snapsrc-")

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
    snap_resp = client.create_cluster_snapshot(
        clusterArn=cluster_arn, snapshotName=snapshot_name, tags={"sim2real-check": CHECK}
    )
    snapshot = snap_resp["snapshot"]
    snapshot_arn = snapshot["snapshotArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_snapshot(client, snapshot_arn))
    assert snapshot["status"] in ("CREATING", "ACTIVE"), (
        f"expected snapshot status CREATING or ACTIVE right after CreateClusterSnapshot, "
        f"got {snapshot['status']!r}"
    )

    active_snapshot = _wait_for_snapshot_status(client, snapshot_arn, {"ACTIVE"})
    assert active_snapshot["snapshotName"] == snapshot_name.lower(), (
        f"expected snapshotName {snapshot_name.lower()!r}, got {active_snapshot['snapshotName']!r}"
    )
    assert active_snapshot["snapshotType"] == "MANUAL", (
        f"expected snapshotType MANUAL for a user-invoked CreateClusterSnapshot, "
        f"got {active_snapshot['snapshotType']!r}"
    )
    assert active_snapshot["clusterArn"] == cluster_arn, (
        f"expected snapshot clusterArn {cluster_arn!r}, got {active_snapshot['clusterArn']!r}"
    )
    assert active_snapshot["adminUserName"] == _ADMIN_USER, (
        f"expected snapshot adminUserName {_ADMIN_USER!r}, got {active_snapshot['adminUserName']!r}"
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


def _best_effort_delete_cluster(client, cluster_arn, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            client.delete_cluster(clusterArn=cluster_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException":
                # e.g. the cluster is still CREATING; retry until it settles into a deletable state.
                time.sleep(interval_s)
                continue
            raise


def _best_effort_delete_snapshot(client, snapshot_arn, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            client.delete_cluster_snapshot(snapshotArn=snapshot_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException":
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
