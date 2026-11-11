"""neptune-graph-execute-query-during-graph-creation-conflict."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError, EndpointConnectionError

from behavioral_harness import tags

CHECK = "neptune-graph-execute-query-during-graph-creation-conflict"
GROUP = "error-semantics"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteQuery against a graph still in CREATING fails with ResourceNotFoundException (the data plane
    cannot resolve the graph id yet, rather than reporting a state conflict); the same query succeeds
    once the graph reaches AVAILABLE."""
    ng = ctx.client("neptune-graph")
    name = ctx.unique_name("sim2real-ng-")
    graph_id = ng.create_graph(
        graphName=name,
        provisionedMemory=16,
        deletionProtection=False,
        publicConnectivity=True,
        tags={"sim2real-created-at": "create-time"},
    )["id"]
    ctx.on_cleanup(lambda: _force_delete_graph(ng, graph_id))

    creating_status = ng.get_graph(graphIdentifier=graph_id)["status"]
    assert creating_status == "CREATING", f"expected freshly-created graph to be CREATING, got {creating_status}"

    code, msg = _error_awaiting_endpoint(
        lambda: ng.execute_query(
            graphIdentifier=graph_id, queryString="RETURN 1 AS one", language="OPEN_CYPHER"
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException while graph is CREATING (data-plane endpoint not yet "
        f"registered), got {code!r}"
    )
    expected = f"No graph found for customer [{ctx.account}] with graph id [{graph_id}]"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    final = _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id),
        lambda g: g["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=900,
        interval_s=15,
    )
    assert final["status"] == "AVAILABLE", f"expected graph to reach AVAILABLE, ended in {final['status']!r}"

    data = _run_query(ng, graph_id, "RETURN 1 AS one")
    assert data["results"] == [{"one": 1}], f"expected [{{'one': 1}}] once AVAILABLE, got {data!r}"


# ===== helpers =====
def _run_query(ng, graph_id, query_string, parameters=None):
    kwargs = {"graphIdentifier": graph_id, "queryString": query_string, "language": "OPEN_CYPHER"}
    if parameters is not None:
        kwargs["parameters"] = parameters
    resp = ng.execute_query(**kwargs)
    return json.loads(resp["payload"].read())


def _error_awaiting_endpoint(fn, *, timeout_s=120.0, interval_s=5.0):
    """The per-graph data-plane endpoint is not immediately resolvable right after CreateGraph;
    retry past EndpointConnectionError (DNS/routing not yet live) until the data plane itself
    answers with a ClientError, then return that error's (code, message). Raises on unexpected success."""
    deadline = time.monotonic() + timeout_s
    last_conn_err = None
    while True:
        try:
            result = fn()
        except ClientError as e:
            err = e.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        except EndpointConnectionError as e:
            last_conn_err = e
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"data-plane endpoint never became reachable within {timeout_s}s: {last_conn_err}"
                ) from e
            time.sleep(interval_s)
            continue
        raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _force_delete_graph(ng, graph_id):
    def _settle(timeout_s):
        return _poll_until(
            lambda: ng.get_graph(graphIdentifier=graph_id),
            lambda g: g["status"] in ("AVAILABLE", "FAILED", "STOPPED"),
            timeout_s=timeout_s,
            interval_s=2,
        )

    try:
        if _settle(900).get("deletionProtection"):
            ng.update_graph(graphIdentifier=graph_id, deletionProtection=False)
            _settle(120)
        ng.delete_graph(graphIdentifier=graph_id, skipSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
