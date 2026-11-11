"""delete-graph-removes-from-list-graphs."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-graph-removes-from-list-graphs"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """After DeleteGraph, the graph leaves ListGraphs, and ListMembers and UpdateDatasourcePackages on its ARN
    fail with ResourceNotFoundException "Graph not found"."""
    from botocore.exceptions import ClientError

    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)

    d.delete_graph(GraphArn=arn)

    try:
        graphs = _poll_until(
            probe=lambda: _list_all_graph_arns(d),
            predicate=lambda arns: arn not in arns,
            timeout_s=90.0,
            interval_s=3.0,
        )
        assert arn not in graphs, f"graph {arn!r} still present after DeleteGraph: {graphs!r}"

        # The deleted graph must also be unusable, not merely absent from the list: an
        # independent read scoped to it, and a mutation against it, must both reject it by
        # the specific not-found code rather than a generic error or a silent success.
        try:
            d.list_members(GraphArn=arn)
            raise AssertionError(f"expected ResourceNotFoundException reading deleted graph {arn!r}, got success")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            assert code == "ResourceNotFoundException", f"ListMembers on deleted graph: expected ResourceNotFoundException, got {code!r}"
            message = e.response["Error"].get("Message")
            assert message == "Graph not found", f"ListMembers on deleted graph: unexpected message {message!r}"

        try:
            d.update_datasource_packages(GraphArn=arn, DatasourcePackages=["DETECTIVE_CORE"])
            raise AssertionError(f"expected ResourceNotFoundException mutating deleted graph {arn!r}, got success")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            assert code == "ResourceNotFoundException", f"UpdateDatasourcePackages on deleted graph: expected ResourceNotFoundException, got {code!r}"
            message = e.response["Error"].get("Message")
            assert message == "Graph not found", f"UpdateDatasourcePackages on deleted graph: unexpected message {message!r}"
    finally:
        # Recreate a graph so the account keeps the behavior graph it started with.
        new_arn = _create_graph_with_retry(d)
        ctx.on_cleanup(lambda: _delete_graph_quietly(d, new_arn))


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


def _delete_graph_quietly(d, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        d.delete_graph(GraphArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
