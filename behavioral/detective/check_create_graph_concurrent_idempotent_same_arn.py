"""create-graph-concurrent-idempotent-same-arn."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "create-graph-concurrent-idempotent-same-arn"
GROUP = "concurrency"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """Concurrent CreateGraph calls all succeed with the same ARN, and ListGraphs shows exactly that one graph:
    CreateGraph is documented to always return the account's one behavior graph."""
    d = ctx.client("detective")
    # An account administers at most one behavior graph per Region; CreateGraph returns that
    # graph, so it is left in place.
    _create_graph_with_retry(d)  # ensure it exists at least once before racing, cheaply

    with ThreadPoolExecutor(max_workers=8) as pool:
        arns = list(pool.map(lambda _: d.create_graph()["GraphArn"], range(8)))

    unique_arns = set(arns)
    assert len(unique_arns) == 1, f"expected every concurrent CreateGraph to agree on one ARN, got {unique_arns!r}"

    listed = _list_all_graph_arns(d)
    assert listed == list(unique_arns), f"expected ListGraphs to show exactly the one graph, got {listed!r}"


def _create_graph_with_retry(d, retries: int = 8, base_delay: float = 5.0) -> str:
    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            return d.create_graph()["GraphArn"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < retries - 1:
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise AssertionError("create_graph did not succeed after retries")


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
