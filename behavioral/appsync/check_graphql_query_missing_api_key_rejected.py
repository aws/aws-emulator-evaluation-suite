"""graphql-query-missing-api-key-rejected."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "graphql-query-missing-api-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]

SCHEMA_SDL = (
    "type Query {\n  echo(msg: String): String\n}\n\nschema {\n  query: Query\n}\n"
)

JS_CODE = (
    # A "NONE" data source performs no actual invocation, so the value returned by
    # request() is NOT automatically wired up as ctx.result in response() (verified
    # against real AWS: a plain `return { payload: ... }` / `ctx.result.payload`
    # pairing leaves ctx.result null and the field always resolves to null).
    # runtime.earlyReturn() is the documented way to produce a result from a
    # NONE/local resolver without a real backend call: it short-circuits request()
    # and feeds its argument to response() as ctx.result.
    "import { runtime } from '@aws-appsync/utils';\n"
    "export function request(ctx) {\n  runtime.earlyReturn(ctx.args.msg);\n  return {};\n}\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A GraphQL request against an API_KEY-authenticated API without an x-api-key
    header is rejected with HTTP 401/Unauthorized and never reaches the resolver
    (no data is returned); the same query WITH a valid key succeeds (positive control)."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx, appsync)
    _create_schema(ctx, appsync, api["apiId"], SCHEMA_SDL)
    appsync.create_data_source(apiId=api["apiId"], name="noneDs", type="NONE")
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

    # Positive control: with a valid key the query succeeds and returns data.
    # A freshly created resolver/API key can take a few seconds to propagate through
    # AppSync's data plane; immediately after creation a query can come back HTTP 200
    # with `data` present but the field still null, so wait for the actual expected
    # value rather than merely "data is not None".
    ok_body = _poll_graphql(
        ctx, endpoint,
        query,
        api_key=key,
        variables={"m": "authorized"},
        expect=lambda b: b.get("data", {}).get("echo") == "authorized",
    )
    assert ok_body["data"]["echo"] == "authorized", ok_body

    # Negative: no x-api-key header at all.
    status, body = _graphql_post(ctx, endpoint, query, api_key=None, variables={"m": "nope"})
    assert status == 401, f"expected HTTP 401, got {status}: {body}"
    assert body.get("data") is None, f"unauthorized request must not return data: {body}"
    errors = body.get("errors") or []
    assert len(errors) >= 1, f"expected at least one GraphQL error, got {body}"
    assert errors[0].get("errorType") == "UnauthorizedException", errors[0]


def _create_graphql_api(ctx, appsync):
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
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
    if status not in ("SUCCESS", "ACTIVE"):
        raise AssertionError(f"schema creation did not succeed, status={status}")
    return status


def _poll_graphql(ctx, endpoint, query, api_key=None, variables=None, timeout_s=45.0, expect=None):
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
