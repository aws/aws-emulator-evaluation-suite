"""cluster-lifecycle-active-to-deleted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-lifecycle-active-to-deleted"
GROUP = "state"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster yields ACTIVE; DeleteCluster transitions it to INACTIVE, and the
    dead cluster then rejects a mutating call instead of quietly accepting it."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-cluster-")
    created = ecs.create_cluster(clusterName=name)["cluster"]
    arn = created["clusterArn"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ecs, arn))

    assert created["status"] == "ACTIVE", f"expected ACTIVE on create, got {created['status']}"

    described = ecs.describe_clusters(clusters=[arn])["clusters"]
    assert described and described[0]["status"] == "ACTIVE"
    assert described[0]["clusterName"] == name

    deleted = ecs.delete_cluster(cluster=arn)["cluster"]
    assert deleted["status"] == "INACTIVE", f"expected INACTIVE after delete, got {deleted['status']}"

    def probe():
        rows = ecs.describe_clusters(clusters=[arn])["clusters"]
        return rows[0]["status"] if rows else "GONE"

    final = _poll_until(probe, lambda s: s in ("INACTIVE", "GONE"), timeout_s=30.0, interval_s=3.0)
    assert final in ("INACTIVE", "GONE"), f"cluster status did not settle to INACTIVE/GONE, got {final}"

    code, message = _error(
        lambda: ecs.update_cluster_settings(
            cluster=arn, settings=[{"name": "containerInsights", "value": "enabled"}]
        )
    )
    assert code == "ClientException", (
        f"expected UpdateClusterSettings on the dead cluster to reject with "
        f"ClientException (measured on real AWS), got {code!r}"
    )
    assert message == f"Cluster {name} is not in ACTIVE state", f"unexpected message: {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_cluster(ecs, arn: str) -> None:
    try:
        ecs.delete_cluster(cluster=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
