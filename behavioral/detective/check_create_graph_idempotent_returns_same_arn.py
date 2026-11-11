"""create-graph-idempotent-returns-same-arn."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-graph-idempotent-returns-same-arn"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """Two CreateGraph calls return the same ARN and ListGraphs lists it exactly once: CreateGraph is documented
    to always return the account's one behavior graph."""
    d = ctx.client("detective")
    arn1 = d.create_graph()["GraphArn"]
    # An account administers at most one behavior graph per Region; CreateGraph returns that
    # graph, so it is left in place.

    arn2 = d.create_graph()["GraphArn"]
    assert arn1 == arn2, f"CreateGraph is not idempotent: {arn1!r} != {arn2!r}"

    graphs = _list_all_graph_arns(d)
    assert graphs.count(arn1) == 1, f"expected exactly one graph {arn1!r}, saw {graphs!r}"


def _list_all_graph_arns(d) -> list[str]:
    arns: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = d.list_graphs(**kwargs)
        arns.extend(g["Arn"] for g in resp.get("GraphList", []))
        token = resp.get("NextToken")
        if not token:
            break
    return arns


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
