"""tag-resource-on-snapshot-persists-and-untag-removes."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-on-snapshot-persists-and-untag-removes"
GROUP = "state"
SERVICES = ["docdb-elastic"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource/ListTagsForResource work against a cluster-SNAPSHOT
    resourceArn (not just a cluster arn), and tagging the snapshot never leaks onto its
    parent cluster's own tag set."""
    docdb = ctx.client("docdb-elastic")
    cluster_arn = _create_cluster(ctx)["clusterArn"]
    _register_cluster_cleanup(ctx, cluster_arn)
    _wait_for_cluster_status(ctx, cluster_arn, {"ACTIVE"})

    snapshot_arn = docdb.create_cluster_snapshot(
        clusterArn=cluster_arn, snapshotName=ctx.unique_name("sim2real-docdbe-snap-")
    )["snapshot"]["snapshotArn"]
    _register_snapshot_cleanup(ctx, snapshot_arn)
    _wait_for_snapshot_status(ctx, snapshot_arn, {"ACTIVE"})

    docdb.tag_resource(resourceArn=snapshot_arn, tags={"sim2real-snap-tag": "present"})
    snap_tags = docdb.list_tags_for_resource(resourceArn=snapshot_arn)["tags"]
    assert snap_tags.get("sim2real-snap-tag") == "present", (
        f"expected sim2real-snap-tag=present on snapshot tags, got {snap_tags!r}"
    )

    # The parent cluster's own tags are untouched by tagging the snapshot.
    cluster_tags = docdb.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert "sim2real-snap-tag" not in cluster_tags, (
        f"expected sim2real-snap-tag absent from cluster tags, got {cluster_tags!r}"
    )

    docdb.untag_resource(resourceArn=snapshot_arn, tagKeys=["sim2real-snap-tag"])
    snap_tags_after = docdb.list_tags_for_resource(resourceArn=snapshot_arn)["tags"]
    assert "sim2real-snap-tag" not in snap_tags_after, (
        f"expected sim2real-snap-tag removed after untag, got {snap_tags_after!r}"
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
