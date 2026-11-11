"""list-resolvers-by-function-reflects-pipeline."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-resolvers-by-function-reflects-pipeline"
GROUP = "state"
SERVICES = ["appsync"]

_SCHEMA = "type Query {\n  viaFunctionA: String\n  viaFunctionB: String\n}\n"
_PASSTHROUGH = '{"version":"2018-05-29","payload":{}}'


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResolversByFunction returns only the PIPELINE resolvers whose pipelineConfig references
    that functionId, excluding a resolver that uses a different function."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    api_id = api["apiId"]
    _start_schema_and_wait(ctx, api_id, _SCHEMA)
    ds_name = _create_none_datasource(ctx, api_id)

    function_a = _create_function(ctx, appsync, api_id, ds_name)
    function_b = _create_function(ctx, appsync, api_id, ds_name)

    _create_pipeline_resolver(appsync, api_id, "viaFunctionA", function_a)
    _create_pipeline_resolver(appsync, api_id, "viaFunctionB", function_b)

    resolvers_a = appsync.list_resolvers_by_function(apiId=api_id, functionId=function_a)[
        "resolvers"
    ]
    assert len(resolvers_a) == 1, (
        f"expected exactly 1 resolver for function_a, got {len(resolvers_a)}: {resolvers_a}"
    )
    assert resolvers_a[0]["typeName"] == "Query", (
        f"expected typeName Query, got {resolvers_a[0]['typeName']!r}"
    )
    assert resolvers_a[0]["fieldName"] == "viaFunctionA", (
        f"expected fieldName viaFunctionA, got {resolvers_a[0]['fieldName']!r}"
    )
    assert resolvers_a[0]["pipelineConfig"]["functions"] == [function_a], (
        f"expected pipelineConfig.functions == [{function_a}], "
        f"got {resolvers_a[0]['pipelineConfig']['functions']}"
    )

    resolvers_b = appsync.list_resolvers_by_function(apiId=api_id, functionId=function_b)[
        "resolvers"
    ]
    assert len(resolvers_b) == 1, (
        f"expected exactly 1 resolver for function_b, got {len(resolvers_b)}: {resolvers_b}"
    )
    assert resolvers_b[0]["fieldName"] == "viaFunctionB", (
        "functionId filter leaked a resolver belonging to a different function: "
        f"expected viaFunctionB, got {resolvers_b[0]['fieldName']!r}"
    )
    assert resolvers_b[0]["pipelineConfig"]["functions"] == [function_b], (
        f"expected pipelineConfig.functions == [{function_b}], "
        f"got {resolvers_b[0]['pipelineConfig']['functions']}"
    )


def _create_graphql_api(ctx, auth_type="API_KEY"):
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType=auth_type,
        tags={"sim2real": "true"},
    )
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api


def _start_schema_and_wait(ctx, api_id, definition, timeout_s=120.0, interval_s=3.0):
    appsync = ctx.client("appsync")
    appsync.start_schema_creation(apiId=api_id, definition=definition.encode("utf-8"))
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = appsync.get_schema_creation_status(apiId=api_id)
        status = resp["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return status
        if status == "FAILED":
            raise AssertionError(f"schema creation FAILED: {resp.get('details')}")
        time.sleep(interval_s)
    raise AssertionError(f"schema creation incomplete after {timeout_s}s, last={status}")


def _create_none_datasource(ctx, api_id, name=None):
    appsync = ctx.client("appsync")
    ds_name = name or ctx.unique_name("sim2real_ds_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    return ds_name


def _create_function(ctx, appsync, api_id, ds_name):
    return appsync.create_function(
        apiId=api_id,
        name=ctx.unique_name("sim2real_fn_").replace("-", "_"),
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate=_PASSTHROUGH,
        responseMappingTemplate="$util.toJson($ctx.result)",
    )["functionConfiguration"]["functionId"]


def _create_pipeline_resolver(appsync, api_id, field_name, function_id):
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName=field_name,
        kind="PIPELINE",
        pipelineConfig={"functions": [function_id]},
        requestMappingTemplate=_PASSTHROUGH,
        responseMappingTemplate='$util.toJson("done")',
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
