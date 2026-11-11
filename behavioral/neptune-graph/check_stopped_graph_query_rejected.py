"""stopped-graph-query-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "stopped-graph-query-rejected"
GROUP = "overly-permissive"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteQuery against a STOPPED graph is rejected with InternalServerErrorException (not the
    control-plane ConflictException StartGraph uses for state conflicts); restarting the graph makes
    the identical query succeed again."""
    ng = ctx.client("neptune-graph")
    graph_id = _create_available_graph(ctx, ng)

    # Positive control: the exact same query succeeds while the graph is AVAILABLE, before we
    # break anything. Without this, a rejection below cannot be told apart from "this account/query
    # never works at all".
    baseline = _execute_query(ng, graph_id, "RETURN 1 AS x")
    assert baseline["results"][0]["x"] == 1, f"expected query to succeed on AVAILABLE graph, got {baseline!r}"

    ng.stop_graph(graphIdentifier=graph_id)
    _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id)["status"],
        lambda s: s == "STOPPED",
        timeout_s=1500,
        interval_s=15,
    )

    code, msg = _error(lambda: _execute_query(ng, graph_id, "RETURN 1 AS x"))
    assert code == "InternalServerErrorException", f"expected InternalServerErrorException on a STOPPED graph, got {code!r}"
    expected = "Request cannot be processed as graph is unavailable"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # Restore: restarting the graph makes the exact same query succeed again.
    ng.start_graph(graphIdentifier=graph_id)
    _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id)["status"],
        lambda s: s == "AVAILABLE",
        timeout_s=1500,
        interval_s=15,
    )
    result = _execute_query(ng, graph_id, "RETURN 1 AS x")
    assert result["results"][0]["x"] == 1, f"expected query to succeed again after restart, got {result!r}"


# ===== helpers =====
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


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _execute_query(ng, graph_id, query_string, parameters=None):
    kwargs = {"graphIdentifier": graph_id, "queryString": query_string, "language": "OPEN_CYPHER"}
    if parameters is not None:
        kwargs["parameters"] = parameters
    resp = ng.execute_query(**kwargs)
    return json.loads(resp["payload"].read())


def _create_available_graph(ctx, ng, *, provisioned_memory=16, deletion_protection=False, replica_count=0, name=None):
    graph_name = name or ctx.unique_name("sim2real-ng-")
    resp = ng.create_graph(
        graphName=graph_name,
        provisionedMemory=provisioned_memory,
        deletionProtection=deletion_protection,
        replicaCount=replica_count,
        publicConnectivity=True,
        tags={"sim2real": CHECK},
    )
    graph_id = resp["id"]

    def _cleanup() -> None:
        from botocore.exceptions import ClientError

        try:
            _poll_until(
                lambda: ng.get_graph(graphIdentifier=graph_id)["status"],
                lambda s: s not in ("CREATING", "UPDATING", "DELETING", "RESETTING", "STARTING", "STOPPING", "SNAPSHOTTING", "IMPORTING"),
                timeout_s=1500,
                interval_s=2,
            )
            if deletion_protection:
                ng.update_graph(graphIdentifier=graph_id, deletionProtection=False)
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
