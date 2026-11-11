"""create-cluster-snapshot-duplicate-name-conflict-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-snapshot-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["docdb-elastic"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateClusterSnapshot is rejected with ConflictException when a snapshot with the
    same snapshotName already exists for the account, exactly one snapshot ends up under
    that name, while a differently-named snapshot on the same cluster still succeeds (control)."""
    docdb = ctx.client("docdb-elastic")
    arn = _create_cluster(ctx)["clusterArn"]
    _register_cluster_cleanup(ctx, arn)
    docdb.tag_resource(resourceArn=arn, tags={"sim2real-check": CHECK})
    _wait_for_cluster_status(ctx, arn, {"ACTIVE"})

    snapshot_name = ctx.unique_name("sim2real-docdbe-dupsnap-")
    first_arn = docdb.create_cluster_snapshot(clusterArn=arn, snapshotName=snapshot_name)[
        "snapshot"
    ]["snapshotArn"]
    _register_snapshot_cleanup(ctx, first_arn)
    docdb.tag_resource(resourceArn=first_arn, tags={"sim2real-check": CHECK})

    code, message = _error_code(
        lambda: docdb.create_cluster_snapshot(clusterArn=arn, snapshotName=snapshot_name)
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected = "A snapshot already exists with given name"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: exactly one snapshot exists under that name, not two.
    matches = [
        s
        for s in docdb.list_cluster_snapshots(clusterArn=arn, maxResults=20).get("snapshots", [])
        if s["snapshotName"] == snapshot_name.lower()
    ]
    assert len(matches) == 1, f"expected exactly one snapshot named {snapshot_name!r}, got {matches}"

    # Positive control: a differently-named snapshot on the same cluster still succeeds.
    other_name = ctx.unique_name("sim2real-docdbe-othersnap-")
    other_arn = docdb.create_cluster_snapshot(clusterArn=arn, snapshotName=other_name)["snapshot"][
        "snapshotArn"
    ]
    _register_snapshot_cleanup(ctx, other_arn)
    docdb.tag_resource(resourceArn=other_arn, tags={"sim2real-check": CHECK})
    assert other_arn != first_arn, (
        f"expected the differently-named snapshot to be a distinct resource from the "
        f"duplicate-name snapshot, both got snapshotArn {other_arn!r}"
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


def _error_code(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses must not be reported as
    a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected ConflictException, but the call succeeded: {result!r}")


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
