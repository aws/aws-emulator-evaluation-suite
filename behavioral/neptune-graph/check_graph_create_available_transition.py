"""graph-create-available-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "graph-create-available-transition"
GROUP = "state-machine"
SERVICES = ["neptune-graph"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGraph answers CREATING or AVAILABLE, and the graph reaches AVAILABLE with the requested name,
    provisionedMemory 16 and a non-empty endpoint."""
    ng = ctx.client("neptune-graph")
    name = ctx.unique_name("sim2real-ng-")
    resp = ng.create_graph(
        graphName=name,
        provisionedMemory=16,
        replicaCount=0,
        publicConnectivity=False,
        deletionProtection=False,
        tags={"sim2real-created-at": "create-time"},
    )
    graph_id = resp["id"]
    assert resp["status"] in ("CREATING", "AVAILABLE"), f"unexpected initial status {resp['status']!r}"

    def _cleanup() -> None:
        def _settle(timeout_s):
            return _poll_until(
                lambda: ng.get_graph(graphIdentifier=graph_id),
                lambda g: g["status"] not in ("CREATING", "UPDATING"),
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
    assert status == "AVAILABLE", f"graph {graph_id} ended in status {status!r}, expected AVAILABLE"

    final = ng.get_graph(graphIdentifier=graph_id)
    assert final["name"] == name, f"expected name {name!r}, got {final['name']!r}"
    assert final["provisionedMemory"] == 16, f"expected provisionedMemory 16, got {final['provisionedMemory']!r}"
    assert final["status"] == "AVAILABLE", f"expected status AVAILABLE, got {final['status']!r}"
    assert final["endpoint"], "expected a non-empty endpoint on an AVAILABLE graph"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
