"""create-graph-replica-count-out-of-range-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-graph-replica-count-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGraph with replicaCount 5, above the maximum of 2, fails with ValidationException and the exact
    message and lists no graph; replicaCount 0 is accepted and reads back as 0."""
    ng = ctx.client("neptune-graph")
    rejected_name = ctx.unique_name("sim2real-ng-badreplica-")

    code, msg = _error(
        lambda: ng.create_graph(graphName=rejected_name, provisionedMemory=16, replicaCount=5)
    )
    assert code == "ValidationException", f"expected ValidationException for replicaCount=5, got {code!r}"
    expected = (
        "1 validation error detected: Value '5' at 'replicaCount' failed to satisfy constraint: "
        "Member must have value less than or equal to 2"
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    all_names = {g["name"] for g in ng.list_graphs().get("graphs", [])}
    assert rejected_name not in all_names, f"rejected graph {rejected_name!r} unexpectedly appears in list_graphs"

    # Positive control: replicaCount=0 (within [0, 2]) is accepted and the graph really provisions.
    graph_id = _create_available_graph(ctx, ng, replica_count=0)
    final = ng.get_graph(graphIdentifier=graph_id)
    assert final["replicaCount"] == 0, f"expected replicaCount=0 on the provisioned graph, got {final['replicaCount']!r}"


# ===== helpers =====
def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
