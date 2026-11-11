"""list-graph-snapshots-reflects-created-snapshot."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-graph-snapshots-reflects-created-snapshot"
GROUP = "data-plane"
SERVICES = ["neptune-graph"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGraphSnapshots for a graph lists a just-created snapshot exactly once with its name, its
    sourceGraphId and status AVAILABLE."""
    ng = ctx.client("neptune-graph")
    graph_id = _create_available_graph(ctx, ng)

    snap_name = ctx.unique_name("sim2real-ngsnap-")
    snap = ng.create_graph_snapshot(
        graphIdentifier=graph_id,
        snapshotName=snap_name,
        tags={"sim2real-owner": "behavioral-check"},
    )
    snap_id = snap["id"]

    def _try_delete_snap() -> bool:
        try:
            ng.delete_graph_snapshot(snapshotIdentifier=snap_id)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ConflictException":
                return False
            if code != "ResourceNotFoundException":
                raise
        return True

    def _cleanup_snap() -> None:
        # DeleteGraphSnapshot answers ConflictException while the snapshot is still being created.
        _poll_until(_try_delete_snap, bool, timeout_s=300, interval_s=2)

    ctx.on_cleanup(_cleanup_snap)
    _poll_until(
        lambda: ng.get_graph_snapshot(snapshotIdentifier=snap_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=1500,
        interval_s=15,
    )

    listed = ng.list_graph_snapshots(graphIdentifier=graph_id).get("graphSnapshots", [])
    matching = [s for s in listed if s["id"] == snap_id]
    assert len(matching) == 1, f"expected exactly one snapshot {snap_id} in ListGraphSnapshots({graph_id}), found {len(matching)}"
    assert matching[0]["name"] == snap_name, f"expected listed snapshot name {snap_name!r}, got {matching[0]['name']!r}"
    assert matching[0]["sourceGraphId"] == graph_id, f"expected listed sourceGraphId {graph_id}, got {matching[0]['sourceGraphId']!r}"
    assert matching[0]["status"] == "AVAILABLE", f"expected listed snapshot status AVAILABLE, got {matching[0]['status']!r}"


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


def _create_available_graph(ctx, ng, *, provisioned_memory=16, deletion_protection=False, replica_count=0, name=None):
    graph_name = name or ctx.unique_name("sim2real-ng-")
    resp = ng.create_graph(
        graphName=graph_name,
        provisionedMemory=provisioned_memory,
        deletionProtection=deletion_protection,
        replicaCount=replica_count,
        publicConnectivity=False,
        tags={"sim2real-owner": "behavioral-check"},
    )
    graph_id = resp["id"]

    def _cleanup() -> None:
        def _settle(timeout_s):
            return _poll_until(
                lambda: ng.get_graph(graphIdentifier=graph_id),
                lambda g: g["status"] not in ("CREATING", "UPDATING", "DELETING", "RESETTING", "STARTING", "STOPPING", "SNAPSHOTTING", "IMPORTING"),
                timeout_s=timeout_s,
                interval_s=2,
            )

        try:
            if _settle(1200).get("deletionProtection"):
                ng.update_graph(graphIdentifier=graph_id, deletionProtection=False)
                _settle(120)
            ng.delete_graph(graphIdentifier=graph_id, skipSnapshot=True)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    status = _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=1500,
        interval_s=15,
    )
    if status != "AVAILABLE":
        raise AssertionError(f"graph {graph_id} did not reach AVAILABLE (status={status})")
    return graph_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
