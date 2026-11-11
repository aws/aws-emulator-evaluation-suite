"""neptune-graph-list-graphs-pagination-token."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "neptune-graph-list-graphs-pagination-token"
GROUP = "control-plane"
SERVICES = ["neptune-graph"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGraphs with maxResults=1 returns one graph per page, and following nextToken reaches both
    graphs the check created."""
    ng = ctx.client("neptune-graph")
    graph_id_a = _create_available_graph(ctx, ng)
    graph_id_b = _create_available_graph(ctx, ng)

    seen_ids = set()
    page = ng.list_graphs(maxResults=1)
    seen_ids.update(g["id"] for g in page["graphs"])
    assert len(page["graphs"]) == 1, f"maxResults=1 must cap the page at 1 graph, got {page['graphs']!r}"

    pages_fetched = 1
    while "nextToken" in page and page["nextToken"] and pages_fetched < 50:
        page = ng.list_graphs(maxResults=1, nextToken=page["nextToken"])
        seen_ids.update(g["id"] for g in page["graphs"])
        pages_fetched += 1
        if graph_id_a in seen_ids and graph_id_b in seen_ids:
            break

    assert graph_id_a in seen_ids, f"{graph_id_a} missing from paginated ListGraphs results"
    assert graph_id_b in seen_ids, f"{graph_id_b} missing from paginated ListGraphs results"


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
        tags={"sim2real-check": "list-graphs-pagination-token"},
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
