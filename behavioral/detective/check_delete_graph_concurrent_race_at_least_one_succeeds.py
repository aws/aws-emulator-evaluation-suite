"""delete-graph-concurrent-race-at-least-one-succeeds."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-graph-concurrent-race-at-least-one-succeeds"
GROUP = "concurrency"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """Of two DeleteGraph calls released together on the same graph at least one succeeds, a losing call
    answers ResourceNotFoundException, and the graph is gone from ListGraphs. A graph is recreated afterwards so other checks sharing this account still have one."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    barrier = threading.Barrier(2)

    def _attempt(_i: int):
        barrier.wait()
        try:
            d.delete_graph(GraphArn=arn)
            return ("ok", None)
        except ClientError as err:
            return ("err", (err.response["Error"]["Code"], err.response["Error"].get("Message") or ""))

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(_attempt, range(2)))

        assert ("ok", None) in results, f"expected at least one concurrent DeleteGraph call to succeed, got {results!r}"
        losers = [r[1] for r in results if r[0] == "err"]
        assert all(loser == ("ResourceNotFoundException", "") for loser in losers), (
            f"expected a losing DeleteGraph to answer ResourceNotFoundException with an empty message, got {losers!r}"
        )

        remaining = _list_all_graph_arns(d)
        assert arn not in remaining, f"expected {arn!r} gone after the race, got {remaining!r}"
    finally:
        # Restore a graph for the shared account so other checks are not left without one.
        _create_graph_with_retry(d)


def _create_graph_with_retry(d, retries: int = 8, base_delay: float = 5.0) -> str:
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
