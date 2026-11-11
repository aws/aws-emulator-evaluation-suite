"""neptune-graph-create-graph-duplicate-name-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "neptune-graph-create-graph-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGraph with an existing graphName fails with ConflictException and the exact message and leaves
    the original graph's id, provisionedMemory and AVAILABLE status; a unique name creates a distinct graph."""
    ng = ctx.client("neptune-graph")
    original_id = _create_available_graph(ctx, ng, memory=16)
    original_name = ng.get_graph(graphIdentifier=original_id)["name"]

    code, msg = _error(
        lambda: ng.create_graph(
            graphName=original_name, provisionedMemory=32, deletionProtection=False, publicConnectivity=False
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected = f"Graph with name {original_name} already exists!"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # The original graph is untouched (still the same id, memory, status).
    unaffected = ng.get_graph(graphIdentifier=original_id)
    assert unaffected["id"] == original_id, f"expected id {original_id!r}, got {unaffected['id']!r}"
    assert unaffected["provisionedMemory"] == 16, (
        f"expected provisionedMemory 16 (unchanged), got {unaffected['provisionedMemory']!r}"
    )
    assert unaffected["status"] == "AVAILABLE", f"expected status AVAILABLE (unchanged), got {unaffected['status']!r}"

    # Positive control: a distinct name succeeds.
    other_id = _create_available_graph(ctx, ng, memory=16)
    assert other_id != original_id, f"expected a distinct graph id, got the same id {other_id!r} back"


# ===== helpers =====
def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ConflictException, but the call succeeded and returned {result!r}")


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
        tags={"sim2real": CHECK},
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
            if _settle(600).get("deletionProtection"):
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
