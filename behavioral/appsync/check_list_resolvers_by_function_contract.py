"""op-contract-list-resolvers-by-function."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-resolvers-by-function"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_SCHEMA_SDL = b"""
schema {
  query: Query
}
type Query {
  getPost: String
  getComments: String
}
"""

_BOGUS_FUNCTION_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResolversByFunction surfaces exactly the pipeline resolver(s) that reference the given
    function and excludes a resolver wired to a different function; an unknown functionId 404s."""
    appsync = ctx.client("appsync")
    api_id = _create_ready_graphql_api(ctx, _SCHEMA_SDL)
    ds_name = _ident(ctx, "ds")
    fn_name = _ident(ctx, "fn")
    other_fn_name = _ident(ctx, "fn_other")

    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))

    created_fn = appsync.create_function(
        apiId=api_id,
        name=fn_name,
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($context.result)",
    )
    function_id = created_fn["functionConfiguration"]["functionId"]
    ctx.on_cleanup(lambda: appsync.delete_function(apiId=api_id, functionId=function_id))

    # A second function on a different resolver catches a filter that ignores functionId.
    other_fn = appsync.create_function(
        apiId=api_id,
        name=other_fn_name,
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($context.result)",
    )
    other_function_id = other_fn["functionConfiguration"]["functionId"]
    ctx.on_cleanup(lambda: appsync.delete_function(apiId=api_id, functionId=other_function_id))

    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getComments",
        kind="PIPELINE",
        pipelineConfig={"functions": [function_id]},
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.prev.result)",
    )
    ctx.on_cleanup(
        lambda: appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="getComments")
    )

    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getPost",
        kind="PIPELINE",
        pipelineConfig={"functions": [other_function_id]},
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.prev.result)",
    )
    ctx.on_cleanup(
        lambda: appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="getPost")
    )

    resp = appsync.list_resolvers_by_function(apiId=api_id, functionId=function_id)
    seen = {(r["typeName"], r["fieldName"]) for r in resp["resolvers"]}
    assert seen == {("Query", "getComments")}, (
        f"expected only the getComments resolver for functionId={function_id}, got {seen}"
    )
    assert resp["resolvers"][0]["kind"] == "PIPELINE", (
        f"expected kind PIPELINE, got {resp['resolvers'][0]['kind']}"
    )

    other_resp = appsync.list_resolvers_by_function(apiId=api_id, functionId=other_function_id)
    other_seen = {(r["typeName"], r["fieldName"]) for r in other_resp["resolvers"]}
    assert other_seen == {("Query", "getPost")}, (
        f"expected only the getPost resolver for functionId={other_function_id}, got {other_seen}"
    )

    code, msg = _error(
        lambda: appsync.list_resolvers_by_function(apiId=api_id, functionId=_BOGUS_FUNCTION_ID)
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert msg == "Function not found.", f"unexpected message: {msg!r}"


def _ident(ctx, prefix: str) -> str:
    return ctx.unique_name(f"sim2real_{prefix}_").replace("-", "_")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _create_ready_graphql_api(ctx, definition: bytes) -> str:
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)
    appsync.start_schema_creation(apiId=api_id, definition=definition)

    def _probe():
        return appsync.get_schema_creation_status(apiId=api_id)["status"]

    status = _poll_until(_probe, lambda s: s in ("SUCCESS", "ACTIVE", "FAILED"), timeout_s=90.0)
    assert status in ("SUCCESS", "ACTIVE"), f"schema creation ended in {status}"
    return api_id


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
