"""graphql-resolver-util-error-returns-graphql-error."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "graphql-resolver-util-error-returns-graphql-error"
GROUP = "data-plane"
SERVICES = ["appsync"]

SCHEMA_SDL = (
    "type Query {\n  noop: String\n}\n\n"
    "type Mutation {\n  fail(msg: String): String\n}\n\n"
    "schema {\n  query: Query\n  mutation: Mutation\n}\n"
)

JS_CODE = (
    "export function request(ctx) {\n"
    "  util.error(ctx.args.msg, 'CustomError');\n"
    "  return {};\n"
    "}\n"
    "export function response(ctx) {\n"
    "  return ctx.result;\n"
    "}\n"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """util.error() thrown in a resolver's request handler surfaces as a GraphQL
    'errors' entry with the exact message/errorType, and the field's data is null."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx, appsync)
    _create_schema(ctx, appsync, api["apiId"], SCHEMA_SDL)
    appsync.create_data_source(apiId=api["apiId"], name="noneDs", type="NONE")
    appsync.create_resolver(
        apiId=api["apiId"],
        typeName="Mutation",
        fieldName="fail",
        kind="UNIT",
        dataSourceName="noneDs",
        runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
        code=JS_CODE,
    )
    key = appsync.create_api_key(apiId=api["apiId"])["apiKey"]["id"]
    endpoint = api["uris"]["GRAPHQL"]

    mutation = "mutation Fail($m: String) { fail(msg: $m) }"
    body = _poll_graphql(ctx, endpoint, mutation, api_key=key, variables={"m": "boom-custom"})
    assert body["data"]["fail"] is None, body
    errors = body.get("errors") or []
    assert len(errors) == 1, body
    assert errors[0]["message"] == "boom-custom", errors[0]
    assert errors[0]["errorType"] == "CustomError", errors[0]


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


def _poll_graphql(ctx, endpoint, query, api_key=None, variables=None, timeout_s=45.0):
    deadline = time.monotonic() + timeout_s
    last_body = None
    while time.monotonic() < deadline:
        status, last_body = _graphql_post(ctx, endpoint, query, api_key, variables)
        if status == 200 and ("errors" in last_body or last_body.get("data") is not None):
            return last_body
        time.sleep(2.0)
    raise AssertionError(f"graphql endpoint never settled; last={last_body}")


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
