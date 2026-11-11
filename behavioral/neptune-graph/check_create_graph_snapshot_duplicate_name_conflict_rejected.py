"""create-graph-snapshot-duplicate-name-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-graph-snapshot-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGraphSnapshot with a snapshotName already in use fails with ConflictException and the exact
    message and leaves one snapshot of that name, the first; a uniquely named snapshot reaches AVAILABLE."""
    ng = ctx.client("neptune-graph")
    graph_id = _create_available_graph(ctx, ng)

    snap_name = ctx.unique_name("sim2real-ngsnap-")
    first = ng.create_graph_snapshot(
        graphIdentifier=graph_id, snapshotName=snap_name, tags={"sim2real": CHECK}
    )
    first_id = first["id"]
    _register_snapshot_cleanup(ctx, ng, first_id)
    _poll_until(
        lambda: ng.get_graph_snapshot(snapshotIdentifier=first_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=1500,
        interval_s=15,
    )

    code, msg = _error(
        lambda: ng.create_graph_snapshot(graphIdentifier=graph_id, snapshotName=snap_name)
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected = f"Snapshot with name {snap_name} already exists!"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # Effect absent: exactly one snapshot exists under that name (the first one), not two.
    snapshots = ng.list_graph_snapshots(graphIdentifier=graph_id).get("graphSnapshots", [])
    matching = [s for s in snapshots if s["name"] == snap_name]
    assert len(matching) == 1, f"expected exactly 1 snapshot named {snap_name!r}, found {len(matching)}"
    assert matching[0]["id"] == first_id, (
        f"expected the surviving snapshot to be the first one ({first_id!r}), got {matching[0]['id']!r}"
    )

    # Positive control: a genuinely unique snapshot name on the same graph still succeeds.
    other_name = ctx.unique_name("sim2real-ngsnap2-")
    second = ng.create_graph_snapshot(
        graphIdentifier=graph_id, snapshotName=other_name, tags={"sim2real": CHECK}
    )
    second_id = second["id"]
    _register_snapshot_cleanup(ctx, ng, second_id)
    status = _poll_until(
        lambda: ng.get_graph_snapshot(snapshotIdentifier=second_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=1500,
        interval_s=15,
    )
    assert status == "AVAILABLE", f"expected the uniquely-named snapshot to reach AVAILABLE, got {status!r}"


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
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _register_snapshot_cleanup(ctx, ng, snapshot_id):
    def _try_delete():
        try:
            ng.delete_graph_snapshot(snapshotIdentifier=snapshot_id)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ConflictException":
                return False
            if code != "ResourceNotFoundException":
                raise
        return True

    def _cleanup():
        # DeleteGraphSnapshot answers ConflictException while the snapshot is still being created.
        _poll_until(_try_delete, bool, timeout_s=240, interval_s=2)

    ctx.on_cleanup(_cleanup)


def _create_available_graph(ctx, ng, *, provisioned_memory=16, deletion_protection=False, replica_count=0, name=None):
    graph_name = name or ctx.unique_name("sim2real-ng-")
    resp = ng.create_graph(
        graphName=graph_name,
        provisionedMemory=provisioned_memory,
        deletionProtection=deletion_protection,
        replicaCount=replica_count,
        publicConnectivity=False,
        tags={"sim2real": CHECK},
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
            if _settle(900).get("deletionProtection"):
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
