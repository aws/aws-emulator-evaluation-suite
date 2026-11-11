"""concurrent-update-cluster-shard-capacity-conflict."""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-cluster-shard-capacity-conflict"
GROUP = "concurrency"
SERVICES = ["docdb-elastic"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Of two concurrent UpdateCluster calls changing shardCapacity on one ACTIVE cluster, exactly one is
    accepted and the other fails with ConflictException "Can't perform operation on cluster as it's in use",
    and the cluster settles ACTIVE with the accepted capacity."""
    docdb = ctx.client("docdb-elastic")
    arn = _create_cluster(ctx, shardCapacity=2)["clusterArn"]
    _register_cluster_cleanup(ctx, arn)
    _wait_for_cluster_status(ctx, arn, {"ACTIVE"})

    def _attempt(capacity):
        try:
            docdb.update_cluster(clusterArn=arn, shardCapacity=capacity)
            return ("ok", capacity)
        except ClientError as exc:
            return ("error", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_attempt, [4, 8]))

    successes = [r for kind, r in results if kind == "ok"]
    errors = [r for kind, r in results if kind == "error"]

    assert len(successes) == 1, f"expected exactly one accepted UpdateCluster, got {results}"
    assert len(errors) == 1, f"expected exactly one rejected UpdateCluster, got {results}"
    assert errors[0][0] == "ConflictException", f"expected ConflictException, got {errors[0]!r}"
    assert errors[0][1] == "Can't perform operation on cluster as it's in use", f"unexpected message: {errors[0]!r}"

    final = _wait_for_cluster_status(ctx, arn, {"ACTIVE"})
    assert final["shardCapacity"] == successes[0], (
        f"final shardCapacity {final['shardCapacity']} does not match the accepted "
        f"request {successes[0]}"
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
