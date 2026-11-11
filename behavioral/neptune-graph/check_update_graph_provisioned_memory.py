"""update-graph-provisioned-memory."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-graph-provisioned-memory"
GROUP = "state-machine"
SERVICES = ["neptune-graph"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGraph answers UPDATING or AVAILABLE, and once the graph is AVAILABLE again GetGraph reports
    provisionedMemory 32."""
    ng = ctx.client("neptune-graph")
    graph_id = _create_available_graph(ctx, ng, provisioned_memory=16)

    update_resp = ng.update_graph(graphIdentifier=graph_id, provisionedMemory=32)
    assert update_resp["status"] in ("UPDATING", "AVAILABLE"), (
        f"UpdateGraph's own response reported status {update_resp['status']!r}, "
        "expected UPDATING (in-flight) or AVAILABLE (already converged)"
    )
    status = _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=1500,
        interval_s=15,
    )
    assert status == "AVAILABLE", f"graph {graph_id} ended update in status {status!r}, expected AVAILABLE"

    final = ng.get_graph(graphIdentifier=graph_id)
    assert final["provisionedMemory"] == 32, (
        f"expected provisionedMemory=32 after UpdateGraph converged, got {final['provisionedMemory']!r}"
    )


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
        tags={"sim2real-created-at": "create-time"},
    )
    graph_id = resp["id"]

    def _cleanup() -> None:
        from botocore.exceptions import ClientError

        try:
            _poll_until(
                lambda: ng.get_graph(graphIdentifier=graph_id)["status"],
                lambda s: s not in ("CREATING", "UPDATING", "DELETING", "RESETTING", "STARTING", "STOPPING", "SNAPSHOTTING", "IMPORTING"),
                timeout_s=1500,
                interval_s=2,
            )
            if deletion_protection:
                ng.update_graph(graphIdentifier=graph_id, deletionProtection=False)
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
