"""copy-cluster-snapshot-success."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "copy-cluster-snapshot-success"
GROUP = "state"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASSWORD = "Sim2RealPassw0rd123"


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CopyClusterSnapshot on an ACTIVE source snapshot transitions the copy
    (none) -> COPYING -> ACTIVE; the copy gets a distinct snapshotArn/snapshotName but
    references the same source clusterArn, and is always snapshotType MANUAL."""
    client = ctx.client("docdb-elastic")
    cluster_name = ctx.unique_name("sim2real-elastic-copysrc-")

    cluster_arn = client.create_cluster(
        clusterName=cluster_name,
        authType="PLAIN_TEXT",
        adminUserName=_ADMIN_USER,
        adminUserPassword=_ADMIN_PASSWORD,
        shardCapacity=2,
        shardCount=1,
        tags={"sim2real-check": CHECK},
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_cluster(client, cluster_arn))
    _wait_for_status(client, cluster_arn, "get_cluster", "cluster", {"ACTIVE"})

    source_name = ctx.unique_name("sim2real-elastic-src-snap-")
    source_arn = client.create_cluster_snapshot(
        clusterArn=cluster_arn,
        snapshotName=source_name,
        tags={"sim2real-check": CHECK},
    )["snapshot"]["snapshotArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_snapshot(client, source_arn))
    _wait_for_status(client, source_arn, "get_cluster_snapshot", "snapshot", {"ACTIVE"})

    target_name = ctx.unique_name("sim2real-elastic-copy-snap-")
    copy_resp = client.copy_cluster_snapshot(
        snapshotArn=source_arn,
        targetSnapshotName=target_name,
        tags={"sim2real-check": CHECK},
    )
    copy_arn = copy_resp["snapshot"]["snapshotArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_snapshot(client, copy_arn))
    assert copy_arn != source_arn, (
        f"expected the copy snapshot ARN to differ from the source ARN, both were {source_arn!r}"
    )

    active_copy = _wait_for_status(client, copy_arn, "get_cluster_snapshot", "snapshot", {"ACTIVE"})
    assert active_copy["snapshotName"] == target_name.lower(), (
        f"expected copy snapshotName {target_name.lower()!r}, got {active_copy['snapshotName']!r}"
    )
    assert active_copy["clusterArn"] == cluster_arn, (
        f"expected copy to reference source clusterArn {cluster_arn!r}, "
        f"got {active_copy['clusterArn']!r}"
    )
    assert active_copy["snapshotType"] == "MANUAL", (
        f"expected copy snapshotType 'MANUAL', got {active_copy['snapshotType']!r}"
    )


def _wait_for_status(client, arn, get_op, result_key, target_statuses, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    arn_kw = "clusterArn" if result_key == "cluster" else "snapshotArn"
    while time.monotonic() < deadline:
        result = getattr(client, get_op)(**{arn_kw: arn})[result_key]
        last_status = result["status"]
        if last_status in target_statuses:
            return result
        time.sleep(interval_s)
    raise AssertionError(f"{result_key} never reached {target_statuses}, last status={last_status}")


def _best_effort_delete_cluster(client, cluster_arn):
    try:
        client.delete_cluster(clusterArn=cluster_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _best_effort_delete_snapshot(client, snapshot_arn):
    try:
        client.delete_cluster_snapshot(snapshotArn=snapshot_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
