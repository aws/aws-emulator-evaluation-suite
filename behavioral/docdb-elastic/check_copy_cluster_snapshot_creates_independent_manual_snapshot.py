"""copy-cluster-snapshot-creates-independent-manual-snapshot."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-cluster-snapshot-creates-independent-manual-snapshot"
GROUP = "state"
SERVICES = ["docdb-elastic"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CopyClusterSnapshot produces a distinct, ACTIVE, MANUAL-typed snapshot referencing the
    same source cluster, and the copy outlives deletion of the source snapshot."""
    docdb = ctx.client("docdb-elastic")
    cluster_arn = _create_cluster(ctx)["clusterArn"]
    _register_cluster_cleanup(ctx, cluster_arn)
    _wait_for_cluster_status(ctx, cluster_arn, {"ACTIVE"})

    source_arn = docdb.create_cluster_snapshot(
        clusterArn=cluster_arn,
        snapshotName=ctx.unique_name("sim2real-docdbe-src-"),
        tags={"sim2real-check": CHECK},
    )["snapshot"]["snapshotArn"]
    _register_snapshot_cleanup(ctx, source_arn)
    _wait_for_snapshot_status(ctx, source_arn, {"ACTIVE"})

    copy_name = ctx.unique_name("sim2real-docdbe-copy-")
    copy = docdb.copy_cluster_snapshot(
        snapshotArn=source_arn, targetSnapshotName=copy_name, tags={"sim2real-check": CHECK}
    )["snapshot"]
    copy_arn = copy["snapshotArn"]
    _register_snapshot_cleanup(ctx, copy_arn)
    assert copy_arn != source_arn, f"copy snapshotArn {copy_arn!r} must differ from source {source_arn!r}"

    active_copy = _wait_for_snapshot_status(ctx, copy_arn, {"ACTIVE"})
    assert active_copy["snapshotType"] == "MANUAL", active_copy["snapshotType"]
    assert active_copy["clusterArn"] == cluster_arn, (
        f"copy clusterArn {active_copy['clusterArn']!r} must reference source cluster {cluster_arn!r}"
    )
    assert active_copy["snapshotName"] == copy_name.lower(), active_copy["snapshotName"]

    # Independence: deleting the source must not affect the copy.
    docdb.delete_cluster_snapshot(snapshotArn=source_arn)
    _wait_until_snapshot_gone(ctx, source_arn)
    still_active = docdb.get_cluster_snapshot(snapshotArn=copy_arn)["snapshot"]
    assert still_active["status"] == "ACTIVE", still_active["status"]

    # The source is not just absent from a list — a mutation on its dead id fails too.
    try:
        docdb.delete_cluster_snapshot(snapshotArn=source_arn)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"delete on already-deleted source snapshot should be ResourceNotFoundException, "
            f"got {exc.response['Error']['Code']!r}"
        )
        message = exc.response["Error"].get("Message")
        assert message == "Unable to find the snapshot", (
            f"expected message 'Unable to find the snapshot', got {message!r}"
        )
    else:
        raise AssertionError("delete_cluster_snapshot on an already-deleted snapshot unexpectedly succeeded")


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


def _wait_until_snapshot_gone(ctx, arn, timeout_s=900.0, interval_s=10.0):
    docdb = ctx.client("docdb-elastic")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            docdb.get_cluster_snapshot(snapshotArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"snapshot {arn} was not removed within {timeout_s}s")


def _register_cluster_cleanup(ctx, arn):
    def _cleanup():
        docdb = ctx.client("docdb-elastic")
        # fits the suite's 900 s cleanup budget
        deadline = time.monotonic() + 840.0
        while time.monotonic() < deadline:
            try:
                docdb.delete_cluster(clusterArn=arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code == "ConflictException":
                    try:
                        status = docdb.get_cluster(clusterArn=arn)["cluster"]["status"]
                    except ClientError as err:
                        if err.response["Error"]["Code"] != "ResourceNotFoundException":
                            raise
                        return
                    if status == "STOPPED":
                        try:
                            docdb.start_cluster(clusterArn=arn)
                        except ClientError as err:
                            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                                raise
                    time.sleep(2.0)
                    continue
                raise
        raise AssertionError(f"cluster {arn} still refused DeleteCluster after 840 s")

    ctx.on_cleanup(_cleanup)


def _register_snapshot_cleanup(ctx, arn):
    def _cleanup():
        docdb = ctx.client("docdb-elastic")
        try:
            docdb.delete_cluster_snapshot(snapshotArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
