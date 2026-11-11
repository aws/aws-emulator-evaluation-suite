"""flush-api-cache-immediate-clear."""
from __future__ import annotations

import time

from behavioral_harness import tags

# Marks a resource the target accepted but never brought to its ready state, as a failure.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """Build (not raise) the never-ready verdict so a call site keeps its ``from exc`` chaining."""
    return AssertionError(f"{STATE_MARKER}: {msg}")


def _poll_until(probe, predicate, *, timeout_s=900, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _alnum(ctx, prefix):
    """A unique name with NO hyphens — required for DataSource names (``[_A-Za-z][_0-9A-Za-z]*``)."""
    return ctx.unique_name(prefix).replace("-", "_")

CHECK = "flush-api-cache-immediate-clear"
GROUP = 'api-cache'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With FULL_REQUEST_CACHING, identical queries to a $util.autoId() resolver get the same id.

    After FlushApiCache a query sees a new id although most of the 3600s ttl remains."""

    import requests

    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real-behav-check": CHECK},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    graphql_url = api.get("uris", {}).get("GRAPHQL")
    if not graphql_url:
        raise AssertionError("GraphQL API exposed no GRAPHQL endpoint URI")

    # Kick off cache provisioning immediately: real AWS's underlying ElastiCache-class node can take
    # well past 200s to leave CREATING, so starting it here lets that async work run concurrently
    # with the schema/data-source/resolver setup below instead of only after it.
    svc.create_api_cache(apiId=api_id, ttl=3600, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL")
    ctx.on_cleanup(lambda: svc.delete_api_cache(apiId=api_id))

    key = svc.create_api_key(apiId=api_id, description="sim2real-behav key")["apiKey"]

    svc.start_schema_creation(apiId=api_id, definition="schema { query: Query }\ntype Query { freshId: String }".encode("utf-8"))
    _sc = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=900, interval_s=2.0, description="schema creation to reach a terminal state",
    )
    assert _sc["status"] in ("SUCCESS", "ACTIVE"), f"schema creation failed: {_sc.get('details')!r}"

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="freshId",
        dataSourceName=ds["name"],
        requestMappingTemplate='{"version": "2018-05-29", "payload": {"id": "$util.autoId()"}}',
        responseMappingTemplate="$util.toJson($ctx.result.id)",
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="freshId"))

    def _get_cache():
        return svc.get_api_cache(apiId=api_id)["apiCache"]

    state = _poll_until(
        _get_cache, lambda c: c["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=900, interval_s=10.0, description="ApiCache to reach AVAILABLE",
    )
    # No caching effect is observable before AVAILABLE, so a cache stuck in CREATING fails.
    if state["status"] != "AVAILABLE":
        raise _never_ready(
            f"ApiCache did not reach 'AVAILABLE' within this check's polling budget "
            f"(last observed status={state['status']!r})",
        )

    query = "query { freshId }"
    headers = {"x-api-key": key["id"], "Content-Type": "application/json"}

    def _gql():
        routed_url, route_headers = ctx.endpoint_route(graphql_url)
        r = requests.post(routed_url, json={"query": query, "variables": {}}, headers={**headers, **route_headers}, timeout=30)
        body = r.json() if r.content else {}
        assert not body.get("errors"), f"expected no GraphQL errors, got {body.get('errors')!r}"
        return (body.get("data") or {}).get("freshId")

    id1 = _gql()
    id2 = _gql()
    assert id1 == id2, (
        f"expected the second identical query to be served from cache (same id), got {id1!r} vs {id2!r}"
    )

    svc.flush_api_cache(apiId=api_id)

    id3 = _poll_until(
        _gql, lambda v: v != id1, timeout_s=900, interval_s=3.0,
        description="a NEW id to be observed immediately after FlushApiCache",
    )
    assert id3 != id1, (
        f"expected FlushApiCache to IMMEDIATELY evict the cached entry despite ~3600s of ttl "
        f"remaining, still got {id3!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
