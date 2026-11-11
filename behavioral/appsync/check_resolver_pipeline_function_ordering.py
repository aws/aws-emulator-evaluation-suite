"""resolver-pipeline-function-ordering."""
from __future__ import annotations

import time

from behavioral_harness import tags

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _alnum(ctx, prefix):
    """A unique name with NO hyphens — required for Function names (``[_A-Za-z][_0-9A-Za-z]*``)."""
    return ctx.unique_name(prefix).replace("-", "_")

CHECK = "resolver-pipeline-function-ordering"
GROUP = 'resolver'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A PIPELINE resolver runs its functions in the declared order (ctx.stash.trace records it), and
    reordering them with UpdateResolver reverses the order a live GraphQL request observes."""

    import requests

    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY",
        tags={"sim2real": CHECK},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    graphql_url = api.get("uris", {}).get("GRAPHQL")
    if not graphql_url:
        raise AssertionError("GraphQL API exposed no GRAPHQL endpoint URI")
    key = svc.create_api_key(apiId=api_id, description="sim2real-behav key")["apiKey"]

    svc.start_schema_creation(apiId=api_id, definition="schema { query: Query }\ntype Query { order: String }".encode("utf-8"))
    _sc = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=90, interval_s=2.0, description="schema creation to reach a terminal state",
    )
    assert _sc["status"] in ("SUCCESS", "ACTIVE"), f"schema creation failed: {_sc.get('details')!r}"

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))

    fn_a = svc.create_function(
        apiId=api_id, name=_alnum(ctx, "fn"), dataSourceName=ds["name"], functionVersion="2018-05-29",
        requestMappingTemplate=(
            '#set($cur = $util.defaultIfNull($ctx.stash.trace, ""))'
            '#set($ctx.stash.trace = "${cur}A")'
            "{}"
        ),
        responseMappingTemplate="$util.toJson({})",
    )["functionConfiguration"]
    ctx.on_cleanup(lambda _f=fn_a["functionId"]: svc.delete_function(apiId=api_id, functionId=_f))
    fn_b = svc.create_function(
        apiId=api_id, name=_alnum(ctx, "fn"), dataSourceName=ds["name"], functionVersion="2018-05-29",
        requestMappingTemplate=(
            '#set($cur = $util.defaultIfNull($ctx.stash.trace, ""))'
            '#set($ctx.stash.trace = "${cur}B")'
            "{}"
        ),
        responseMappingTemplate="$util.toJson({})",
    )["functionConfiguration"]
    ctx.on_cleanup(lambda _f=fn_b["functionId"]: svc.delete_function(apiId=api_id, functionId=_f))

    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="order",
        kind="PIPELINE",
        pipelineConfig={"functions": [fn_a["functionId"], fn_b["functionId"]]},
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.stash.trace)",
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="order"))

    headers = {"x-api-key": key["id"], "Content-Type": "application/json"}

    def _gql():
        routed_url, route_headers = ctx.endpoint_route(graphql_url)
        r = requests.post(routed_url, json={"query": "query { order }", "variables": {}}, headers={**headers, **route_headers}, timeout=30)
        body = r.json() if r.content else {}
        assert not body.get("errors"), f"expected no GraphQL errors, got {body.get('errors')!r}"
        return (body.get("data") or {}).get("order")

    order1 = _gql()
    assert order1 == "AB", f"expected the pipeline [A, B] to execute in that declared order, got {order1!r}"

    svc.update_resolver(
        apiId=api_id, typeName="Query", fieldName="order",
        kind="PIPELINE",
        pipelineConfig={"functions": [fn_b["functionId"], fn_a["functionId"]]},
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.stash.trace)",
    )

    # Confirm the CONTROL plane immediately reflects the reordered pipeline (distinct from whether
    # the DATA plane has picked it up yet).
    updated_resolver = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="order")["resolver"]
    assert updated_resolver["pipelineConfig"]["functions"] == [fn_b["functionId"], fn_a["functionId"]], (
        f"expected UpdateResolver to persist the reordered function list, got "
        f"{updated_resolver['pipelineConfig']!r}"
    )

    # A resolver config change can take a short while to propagate to the data plane; poll a generous
    # window before concluding the reorder had no observable effect.
    order2 = _poll_until(
        _gql, lambda v: v == "BA", timeout_s=90, interval_s=5.0,
        description="the reordered pipeline execution sequence to propagate to the data plane",
    )
    assert order2 == "BA", (
        f"expected UpdateResolver reordering to [B, A] to change the real execution sequence, got {order2!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
