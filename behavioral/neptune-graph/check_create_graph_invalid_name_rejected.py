"""create-graph-invalid-name-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-graph-invalid-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGraph with a graphName that breaks the naming pattern fails with ValidationException and the exact
    message and lists no such graph; a valid name creates a graph whose id starts with g-."""
    ng = ctx.client("neptune-graph")

    # graphName must match ^(?!g-)[a-z][a-z0-9]*(-[a-z0-9]+)*$ -- a leading digit violates this.
    bad_name = "1" + ctx.unique_name("invalid-ng-").replace("_", "-")
    code, msg = _error(lambda: ng.create_graph(graphName=bad_name, provisionedMemory=16))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        f"1 validation error detected: Value '{bad_name}' at 'graphName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: (?!g-)[a-z][a-z0-9]*(-[a-z0-9]+)*"
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # No graph with the rejected name exists anywhere in the account.
    all_names = {g["name"] for g in ng.list_graphs().get("graphs", [])}
    assert bad_name not in all_names, f"rejected name {bad_name!r} unexpectedly visible in ListGraphs"

    # Positive control: a validly-patterned name is accepted and the graph really provisions.
    graph_id = _create_available_graph(ctx, ng)
    assert graph_id.startswith("g-"), f"expected graph id to start with 'g-', got {graph_id!r}"


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
