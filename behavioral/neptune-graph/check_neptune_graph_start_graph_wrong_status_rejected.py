"""neptune-graph-start-graph-wrong-status-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "neptune-graph-start-graph-wrong-status-rejected"
GROUP = "overly-permissive"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartGraph on an AVAILABLE graph fails with ConflictException and the exact message and leaves it
    AVAILABLE; once the graph is STOPPED, StartGraph brings it back to AVAILABLE."""
    ng = ctx.client("neptune-graph")
    graph_id = _create_available_graph(ctx, ng)

    code, msg = _error(lambda: ng.start_graph(graphIdentifier=graph_id))
    assert code == "ConflictException", code
    expected = "Unable to start the graph because it is in the AVAILABLE state."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    unaffected = ng.get_graph(graphIdentifier=graph_id)
    assert unaffected["status"] == "AVAILABLE", unaffected["status"]

    # Positive control: StartGraph does succeed once the graph is genuinely STOPPED.
    ng.stop_graph(graphIdentifier=graph_id)
    _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id)["status"],
        lambda s: s == "STOPPED",
        timeout_s=600,
        interval_s=15,
    )
    ng.start_graph(graphIdentifier=graph_id)
    final = _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id),
        lambda g: g["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=600,
        interval_s=15,
    )
    assert final["status"] == "AVAILABLE", final["status"]


# ===== helpers =====
def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
