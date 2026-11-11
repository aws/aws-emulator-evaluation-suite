"""create-graph-snapshot-of-graph-in-creating-state-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-graph-snapshot-of-graph-in-creating-state-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGraphSnapshot on a graph still CREATING fails with ValidationException and the exact message
    and lists no snapshot; once the graph is AVAILABLE the same call yields an AVAILABLE snapshot."""
    ng = ctx.client("neptune-graph")
    name = ctx.unique_name("sim2real-ng-")
    resp = ng.create_graph(
        graphName=name,
        provisionedMemory=16,
        publicConnectivity=False,
        tags={"sim2real-owner": "behavioral-check"},
    )
    graph_id = resp["id"]

    def _cleanup_graph() -> None:
        def _settle(timeout_s):
            return _poll_until(
                lambda: ng.get_graph(graphIdentifier=graph_id),
                lambda g: g["status"] not in ("CREATING", "UPDATING", "SNAPSHOTTING"),
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

    ctx.on_cleanup(_cleanup_graph)

    # The graph is guaranteed to still be CREATING right after CreateGraph returns (creation
    # takes minutes), so a snapshot attempt right now must land on a non-AVAILABLE graph.
    assert resp["status"] == "CREATING", f"expected freshly created graph status CREATING, got {resp['status']!r}"
    snap_name = ctx.unique_name("sim2real-ngsnap-")
    code, msg = _error(
        lambda: ng.create_graph_snapshot(graphIdentifier=graph_id, snapshotName=snap_name)
    )
    assert code == "ValidationException", f"expected ValidationException for CreateGraphSnapshot on a CREATING graph, got {code!r}"
    expected = (
        f"Graph [{graph_id}] is not available for snapshot. You can only create a snapshot for an AVAILABLE Graph."
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # No snapshot with that name was actually created.
    snapshots = ng.list_graph_snapshots(graphIdentifier=graph_id).get("graphSnapshots", [])
    assert not any(s["name"] == snap_name for s in snapshots), (
        f"expected no snapshot named {snap_name!r} after the rejected create, found one in {snapshots!r}"
    )

    # Positive control: once the graph is AVAILABLE, the exact same snapshot request succeeds.
    status = _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=1500,
        interval_s=15,
    )
    assert status == "AVAILABLE", f"expected graph {graph_id} to reach AVAILABLE, got {status!r}"

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
    snap_status = _poll_until(
        lambda: ng.get_graph_snapshot(snapshotIdentifier=snap_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=1500,
        interval_s=15,
    )
    assert snap_status == "AVAILABLE", f"expected snapshot {snap_id} to reach AVAILABLE, got {snap_status!r}"


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


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
