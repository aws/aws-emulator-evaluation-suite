"""concurrent-merge-no-duplicate-node."""
from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-merge-no-duplicate-node"
GROUP = "concurrency"
SERVICES = ["neptune-graph"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent openCypher MERGE calls on the same key create exactly one node, not N."""
    ng = ctx.client("neptune-graph")
    graph_id = _create_available_graph(ctx, ng)

    key = "acct-" + uuid.uuid4().hex[:8]
    n_racers = 10

    def _merge() -> None:
        _execute_query_retrying_conflicts(
            ng, graph_id, "MERGE (n:Account {id: $id}) RETURN n", parameters={"id": key}
        )

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(_merge) for _ in range(n_racers)]
        for f in futures:
            f.result()

    result = _execute_query(
        ng, graph_id, "MATCH (n:Account {id: $id}) RETURN count(n) AS c", parameters={"id": key}
    )
    count = result["results"][0]["c"]
    assert count == 1, f"expected exactly 1 node for key {key!r} after {n_racers} concurrent MERGE calls, got {count}"


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


def _execute_query(ng, graph_id, query_string, parameters=None):
    kwargs = {"graphIdentifier": graph_id, "queryString": query_string, "language": "OPEN_CYPHER"}
    if parameters is not None:
        kwargs["parameters"] = parameters
    resp = ng.execute_query(**kwargs)
    return json.loads(resp["payload"].read())


def _execute_query_retrying_conflicts(ng, graph_id, query_string, parameters=None, *, deadline_s=30.0):
    """Neptune Analytics answers a racing openCypher write with ConflictException ("please retry",
    HTTP 409) rather than serializing it silently; a correct client is expected to retry."""
    deadline = time.monotonic() + deadline_s
    attempt = 0
    while True:
        try:
            return _execute_query(ng, graph_id, query_string, parameters=parameters)
        except ClientError as e:
            attempt += 1
            if e.response.get("Error", {}).get("Code") != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(min(0.25 * attempt, 2.0))


def _create_available_graph(ctx, ng, *, provisioned_memory=16, deletion_protection=False, replica_count=0, name=None):
    graph_name = name or ctx.unique_name("sim2real-ng-")
    resp = ng.create_graph(
        graphName=graph_name,
        provisionedMemory=provisioned_memory,
        deletionProtection=deletion_protection,
        replicaCount=replica_count,
        publicConnectivity=True,
        tags={"sim2real-owner": "behavioral-check"},
    )
    graph_id = resp["id"]

    def _cleanup() -> None:
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
