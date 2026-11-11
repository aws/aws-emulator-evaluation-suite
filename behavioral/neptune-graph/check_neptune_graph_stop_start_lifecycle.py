"""neptune-graph-stop-start-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "neptune-graph-stop-start-lifecycle"
GROUP = "state"
SERVICES = ["neptune-graph"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopGraph answers STOPPING or STOPPED and the graph settles STOPPED; StartGraph then answers STARTING
    or AVAILABLE and the graph settles AVAILABLE."""
    ng = ctx.client("neptune-graph")
    graph_id = _create_available_graph(ctx, ng)

    stopped = ng.stop_graph(graphIdentifier=graph_id)
    assert stopped["status"] in ("STOPPING", "STOPPED"), (
        f"expected STOPPING or STOPPED right after StopGraph, got {stopped['status']!r}"
    )
    final_stopped = _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id),
        lambda g: g["status"] in ("STOPPED", "FAILED"),
        timeout_s=600,
        interval_s=15,
    )
    assert final_stopped["status"] == "STOPPED", final_stopped["status"]

    started = ng.start_graph(graphIdentifier=graph_id)
    assert started["status"] in ("STARTING", "AVAILABLE"), (
        f"expected STARTING or AVAILABLE right after StartGraph, got {started['status']!r}"
    )
    final_started = _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id),
        lambda g: g["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=600,
        interval_s=15,
    )
    assert final_started["status"] == "AVAILABLE", final_started["status"]


# ===== helpers =====
def _poll_until(probe, predicate, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_available_graph(ctx, ng, memory=16, deletion_protection=False):
    name = ctx.unique_name("sim2real-ng-")
    graph_id = ng.create_graph(
        graphName=name,
        provisionedMemory=memory,
        deletionProtection=deletion_protection,
        publicConnectivity=False,
        tags={"sim2real-created-at": "create-time"},
    )["id"]

    def _cleanup():
        def _settle(timeout_s):
            return _poll_until(
                lambda: ng.get_graph(graphIdentifier=graph_id),
                lambda g: g["status"] in ("AVAILABLE", "FAILED", "STOPPED"),
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
        timeout_s=900,
        interval_s=15,
    )
    if status != "AVAILABLE":
        raise AssertionError(f"graph {graph_id} did not reach AVAILABLE, got {status}")
    return graph_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
