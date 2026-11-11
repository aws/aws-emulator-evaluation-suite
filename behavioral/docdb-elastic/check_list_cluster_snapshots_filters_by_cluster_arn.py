"""list-cluster-snapshots-filters-by-cluster-arn."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-cluster-snapshots-filters-by-cluster-arn"
GROUP = "state"
SERVICES = ["docdb-elastic"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListClusterSnapshots(clusterArn=...) scopes results to snapshots of that specific
    cluster: a snapshot belonging to a sibling cluster must never appear in the page."""
    docdb = ctx.client("docdb-elastic")

    cluster_a = _create_cluster(ctx)
    arn_a = cluster_a["clusterArn"]
    _register_cluster_cleanup(ctx, arn_a)
    _wait_for_cluster_status(ctx, arn_a, {"ACTIVE"})

    cluster_b = _create_cluster(ctx)
    arn_b = cluster_b["clusterArn"]
    _register_cluster_cleanup(ctx, arn_b)
    _wait_for_cluster_status(ctx, arn_b, {"ACTIVE"})

    snap_a_name = ctx.unique_name("sim2real-docdbe-snapa-")
    snap_a_arn = docdb.create_cluster_snapshot(
        clusterArn=arn_a, snapshotName=snap_a_name, tags={"sim2real:managed": "true"}
    )["snapshot"]["snapshotArn"]
    _register_snapshot_cleanup(ctx, snap_a_arn)
    _wait_for_snapshot_status(ctx, snap_a_arn, {"ACTIVE"})

    snap_b_name = ctx.unique_name("sim2real-docdbe-snapb-")
    snap_b_arn = docdb.create_cluster_snapshot(
        clusterArn=arn_b, snapshotName=snap_b_name, tags={"sim2real:managed": "true"}
    )["snapshot"]["snapshotArn"]
    _register_snapshot_cleanup(ctx, snap_b_arn)
    _wait_for_snapshot_status(ctx, snap_b_arn, {"ACTIVE"})

    scoped_arns = _all_snapshot_arns(ctx, cluster_arn=arn_a)
    assert snap_a_arn in scoped_arns, "own snapshot missing from ListClusterSnapshots(clusterArn=)"
    assert snap_b_arn not in scoped_arns, (
        "a sibling cluster's snapshot leaked into a clusterArn-scoped ListClusterSnapshots page"
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
        "tags": {"sim2real:managed": "true"},
    }
    params.update(overrides)
    return docdb.create_cluster(**params)["cluster"]


def _all_snapshot_arns(ctx, cluster_arn, max_pages=10):
    docdb = ctx.client("docdb-elastic")
    arns = []
    token = None
    for _ in range(max_pages):
        kwargs = {"clusterArn": cluster_arn, "maxResults": 20}
        if token:
            kwargs["nextToken"] = token
        resp = docdb.list_cluster_snapshots(**kwargs)
        arns.extend(s["snapshotArn"] for s in resp.get("snapshots", []))
        token = resp.get("nextToken")
        if not token:
            break
    return arns


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


def _register_cluster_cleanup(ctx, arn):
    def _cleanup():
        docdb = ctx.client("docdb-elastic")
        # two cluster teardowns share the suite's 900 s cleanup budget
        deadline = time.monotonic() + 420.0
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
        raise AssertionError(f"cluster {arn} still refused DeleteCluster after 420 s")

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
