"""update-cluster-shard-count-decrease-merges-shard-topology."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-cluster-shard-count-decrease-merges-shard-topology"
GROUP = "state"
SERVICES = ["docdb-elastic"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Decreasing shardCount via UpdateCluster (ACTIVE -> UPDATING/MERGING -> ACTIVE)
    shrinks the cluster's reported shard topology, the mirror direction of a shardCount
    increase (which grows it via SPLITTING)."""
    docdb = ctx.client("docdb-elastic")
    arn = _create_cluster(ctx, shardCount=2)["clusterArn"]
    _register_cluster_cleanup(ctx, arn)
    baseline = _wait_for_cluster_status(ctx, arn, {"ACTIVE"})
    assert baseline["shardCount"] == 2, baseline["shardCount"]
    assert len(baseline.get("shards", [])) == 2, baseline.get("shards")

    docdb.update_cluster(clusterArn=arn, shardCount=1)
    updated = _wait_for_cluster_status(ctx, arn, {"ACTIVE"})
    assert updated["shardCount"] == 1, updated["shardCount"]
    assert len(updated.get("shards", [])) == 1, (
        f"shard topology did not shrink after shardCount decrease: {updated.get('shards')}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
