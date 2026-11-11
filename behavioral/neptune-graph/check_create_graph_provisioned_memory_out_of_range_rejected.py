"""create-graph-provisioned-memory-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.config import Config

from behavioral_harness import tags

CHECK = "create-graph-provisioned-memory-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGraph with provisionedMemory 8, below the minimum of 16, fails with ValidationException and the
    exact message and lists no graph; provisionedMemory 16 is accepted and reads back as 16."""
    ng = ctx.client("neptune-graph")
    rejected_name = ctx.unique_name("sim2real-ng-badmem-")

    # provisionedMemory's model shape carries smithy.api#range(min=16), which botocore compiles
    # into a LOCAL parameter check -- a validating client refuses to even transmit
    # provisionedMemory=8, so it never reaches AWS. Sending it unvalidated is the only way this
    # check can observe the service's own server-side rejection instead of botocore's.
    ng_unvalidated = ctx.client("neptune-graph", config=Config(parameter_validation=False))
    code, msg = _error(lambda: ng_unvalidated.create_graph(graphName=rejected_name, provisionedMemory=8))
    assert code == "ValidationException", f"expected ValidationException for provisionedMemory=8, got {code!r}"
    expected = (
        "1 validation error detected: Value '8' at 'provisionedMemory' failed to satisfy constraint: "
        "Member must have value greater than or equal to 16"
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    all_names = {g["name"] for g in ng.list_graphs().get("graphs", [])}
    assert rejected_name not in all_names, f"{rejected_name} should not exist after a rejected CreateGraph, but list_graphs shows it"

    # Positive control: the minimum allowed value (16) is accepted and the graph really provisions.
    graph_id = _create_available_graph(ctx, ng, provisioned_memory=16)
    final = ng.get_graph(graphIdentifier=graph_id)
    assert final["provisionedMemory"] == 16, f"expected provisionedMemory==16 for the minimum-boundary graph, got {final['provisionedMemory']!r}"


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
        tags={"sim2real-owner": "behavioral-check"},
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
