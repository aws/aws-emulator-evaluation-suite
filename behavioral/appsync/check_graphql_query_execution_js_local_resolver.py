"""graphql-query-execution-js-local-resolver."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "graphql-query-execution-js-local-resolver"
GROUP = "data-plane"
SERVICES = ["appsync"]

SCHEMA_SDL = (
    "type Query {\n"
    "  echo(msg: String): String\n"
    "}\n\n"
    "schema {\n"
    "  query: Query\n"
    "}\n"
)

# A "NONE" data source performs no actual invocation, so the value returned by
# request() is NOT automatically wired up as ctx.result in response() (verified
# against real AWS: with a plain `return { payload: ... }` / `ctx.result.payload`
# pairing, ctx.result is null and the field always resolves to null). The
# documented way to produce a result from a NONE/local resolver without a real
# backend call is `runtime.earlyReturn()`. The response() marker below proves,
# rather than assumes, whether AppSync still invokes response() afterwards.
JS_CODE = (
    "import { runtime } from '@aws-appsync/utils';\n"
    "export function request(ctx) {\n"
    "  runtime.earlyReturn(ctx.args.msg);\n"
    "  return {};\n"
    "}\n"
    "export function response(ctx) {\n"
    "  return 'response-handler-ran:' + ctx.result;\n"
    "}\n"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A UNIT resolver with a NONE data source, written in APPSYNC_JS, actually
    executes and echoes the query argument back through a real GraphQL query."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx, appsync)
    _create_schema(ctx, appsync, api["apiId"], SCHEMA_SDL)
    _create_none_data_source(ctx, appsync, api["apiId"], "noneDs")
    appsync.create_resolver(
        apiId=api["apiId"],
        typeName="Query",
        fieldName="echo",
        kind="UNIT",
        dataSourceName="noneDs",
        runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
        code=JS_CODE,
    )
    key = appsync.create_api_key(apiId=api["apiId"])["apiKey"]["id"]
    endpoint = api["uris"]["GRAPHQL"]

    query = "query Echo($m: String) { echo(msg: $m) }"
    # A freshly created resolver/API key can take a few seconds to propagate through
    # AppSync's data plane; immediately after creation a query can come back HTTP 200
    # with `data` present but the field still null, so the poll predicate must wait for
    # the actual expected value rather than merely "data is not None".
    body = _poll_graphql(
        ctx, endpoint,
        query,
        api_key=key,
        variables={"m": "hello-appsync-js"},
        expect=lambda b: b.get("data", {}).get("echo") is not None,
    )
    assert body.get("errors") in (None, []), f"unexpected errors: {body.get('errors')}"
    # runtime.earlyReturn() in request() must skip response() entirely and hand its
    # argument straight back as the field value -- not merely make it reachable as
    # ctx.result. If response() ran, the field would carry the "response-handler-ran:"
    # marker instead of the bare echoed argument.
    assert body["data"]["echo"] == "hello-appsync-js", body


def _create_graphql_api(ctx, appsync):
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": "behavioral"},
    )
    api = resp["graphqlApi"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api["apiId"]))
    return api


def _create_schema(ctx, appsync, api_id, sdl, timeout_s=90.0):
    appsync.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    deadline = time.monotonic() + timeout_s
    status = "PROCESSING"
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE", "FAILED"):
            break
        time.sleep(2.0)
    if status == "FAILED":
        raise AssertionError("schema creation unexpectedly failed")
    if status not in ("SUCCESS", "ACTIVE"):
        raise AssertionError(f"schema creation did not settle within {timeout_s}s")
    return status


def _create_none_data_source(ctx, appsync, api_id, name):
    appsync.create_data_source(apiId=api_id, name=name, type="NONE")


def _poll_graphql(ctx, endpoint, query, api_key=None, variables=None, timeout_s=60.0, expect=None):
    deadline = time.monotonic() + timeout_s
    last_body = None
    default_expect = lambda b: b.get("data") is not None
    predicate = expect or default_expect
    while time.monotonic() < deadline:
        status, last_body = _graphql_post(ctx, endpoint, query, api_key, variables)
        if status == 200 and predicate(last_body):
            return last_body
        time.sleep(2.0)
    raise AssertionError(f"graphql endpoint never met expectation; last={last_body}")


def _graphql_post(ctx, endpoint, query, api_key=None, variables=None, timeout_s=15.0):
    payload = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["x-api-key"] = api_key
    routed_url, route_headers = ctx.endpoint_route(endpoint)
    req = urllib.request.Request(routed_url, data=payload, headers={**headers, **route_headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
