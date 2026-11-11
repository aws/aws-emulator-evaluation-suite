"""graphql-query-execution-vtl-local-resolver."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "graphql-query-execution-vtl-local-resolver"
GROUP = "data-plane"
SERVICES = ["appsync"]

SCHEMA_SDL = (
    "type Query {\n"
    "  echoVtl(msg: String): String\n"
    "}\n\n"
    "schema {\n"
    "  query: Query\n"
    "}\n"
)

REQUEST_TEMPLATE = (
    '{\n  "version": "2017-02-28",\n  "payload": $util.toJson($context.arguments.msg)\n}'
)
RESPONSE_TEMPLATE = "$util.toJson($context.result)"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A UNIT resolver using classic VTL request/response mapping templates against a
    NONE data source echoes the argument through the real query-execution engine."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx, appsync)
    _create_schema(ctx, appsync, api["apiId"], SCHEMA_SDL)
    appsync.create_data_source(apiId=api["apiId"], name="noneDs", type="NONE")
    appsync.create_resolver(
        apiId=api["apiId"],
        typeName="Query",
        fieldName="echoVtl",
        kind="UNIT",
        dataSourceName="noneDs",
        requestMappingTemplate=REQUEST_TEMPLATE,
        responseMappingTemplate=RESPONSE_TEMPLATE,
    )
    key = appsync.create_api_key(apiId=api["apiId"])["apiKey"]["id"]
    endpoint = api["uris"]["GRAPHQL"]

    query = "query EchoVtl($m: String) { echoVtl(msg: $m) }"
    # A freshly created resolver/API key can take a few seconds to propagate through
    # AppSync's data plane; immediately after creation a query can come back HTTP 200
    # with `data` present but the field still null, so the poll predicate must wait for
    # the actual expected value rather than merely "data is not None" (verified against
    # real AWS).
    body = _poll_graphql(
        ctx, endpoint,
        query,
        api_key=key,
        variables={"m": "hello-vtl"},
        expect=lambda b: b.get("data", {}).get("echoVtl") == "hello-vtl",
    )
    assert body.get("errors") in (None, []), f"unexpected errors: {body.get('errors')}"
    assert body["data"]["echoVtl"] == "hello-vtl", body


def _create_graphql_api(ctx, appsync):
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": "audit"},
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
    predicate = expect or (lambda b: b.get("data") is not None)
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
