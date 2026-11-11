"""list-resolvers-by-function."""
from __future__ import annotations

import time
import re

from behavioral_harness import tags

def _sanitize(name):
    """AppSync data source/function names must match ^[_A-Za-z][_0-9A-Za-z]*$."""
    cleaned = re.sub(r"[^0-9A-Za-z_]", "_", name)
    if not cleaned or not re.match(r"[_A-Za-z]", cleaned[0]):
        cleaned = "n_" + cleaned
    return cleaned

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "list-resolvers-by-function"
GROUP = 'resolver'
SERVICES = ['appsync']
DEFAULT_SCHEMA = """schema {
    query: Query
}

type Query {
    getWidget(id: ID!): Widget
    getWidget2(id: ID!): Widget
    getWidget3(id: ID!): Widget
}

type Widget {
    id: ID!
    name: String
}
"""

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResolversByFunction returns every resolver in the pipeline that references a given
    function, and excludes a resolver that pipelines through a different function."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real-check": CHECK},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    svc.start_schema_creation(apiId=api_id, definition=DEFAULT_SCHEMA)
    _sc = _poll_until(lambda: svc.get_schema_creation_status(apiId=api_id), lambda r: r.get("status") in ("SUCCESS", "ACTIVE", "FAILED"), timeout_s=60, interval_s=1.5, description="schema creation")
    if _sc.get("status") == "FAILED":
        raise AssertionError(f"schema creation failed: {_sc.get('details')}")
    ds = svc.create_data_source(apiId=api_id, name=_sanitize(ctx.unique_name("sim2real-behav-ds_")), type="NONE")["dataSource"]
    ds_name = ds["name"]

    fn = svc.create_function(
        apiId=api_id,
        name=_sanitize(ctx.unique_name("sim2real-behav-fn_")),
        dataSourceName=ds_name,
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
        functionVersion="2018-05-29",
    )["functionConfiguration"]
    function_id = fn["functionId"]

    # A second function, pipelined by a resolver on a THIRD field. Its presence is what makes the
    # terminal read meaningful: a stub that ignores functionId and returns every resolver on the
    # API would pass without it.
    other_fn = svc.create_function(
        apiId=api_id,
        name=_sanitize(ctx.unique_name("sim2real-behav-otherfn_")),
        dataSourceName=ds_name,
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
        functionVersion="2018-05-29",
    )["functionConfiguration"]
    other_function_id = other_fn["functionId"]

    for field in ("getWidget", "getWidget2"):
        svc.create_resolver(
            apiId=api_id,
            typeName="Query",
            fieldName=field,
            kind="PIPELINE",
            pipelineConfig={"functions": [function_id]},
            requestMappingTemplate="{}",
            responseMappingTemplate="$util.toJson($ctx.result)",
        )
    svc.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getWidget3",
        kind="PIPELINE",
        pipelineConfig={"functions": [other_function_id]},
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )

    resolvers = svc.list_resolvers_by_function(apiId=api_id, functionId=function_id)["resolvers"]
    fields = {r["fieldName"] for r in resolvers}
    assert fields == {"getWidget", "getWidget2"}, (
        f"expected exactly the two resolvers pipelined through function_id, got {fields}"
    )

    other_resolvers = svc.list_resolvers_by_function(apiId=api_id, functionId=other_function_id)["resolvers"]
    other_fields = {r["fieldName"] for r in other_resolvers}
    assert other_fields == {"getWidget3"}, (
        f"expected only the resolver pipelined through other_function_id, got {other_fields}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
