"""pipeline-resolver-function-chaining-stash."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "pipeline-resolver-function-chaining-stash"
GROUP = "data-plane"
SERVICES = ["appsync"]

SCHEMA_SDL = (
    "type Query {\n  chainedCounter: Int\n}\n\nschema {\n  query: Query\n}\n"
)

FUNC_A_CODE = (
    "export function request(ctx) {\n  ctx.stash.counter = ctx.stash.counter + 1;\n  return {};\n}\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)
FUNC_B_CODE = (
    "export function request(ctx) {\n  ctx.stash.counter = ctx.stash.counter + 10;\n  return {};\n}\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A PIPELINE resolver chains two AppSync Functions; each mutates ctx.stash and
    the final response reflects the cumulative effect of both functions in order
    (0 -> +1 -> +10 == 11), proving pipeline stash state actually threads through."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx, appsync)
    _create_schema(ctx, appsync, api["apiId"], SCHEMA_SDL)
    appsync.create_data_source(apiId=api["apiId"], name="noneDs", type="NONE")

    runtime = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
    func_a = appsync.create_function(
        apiId=api["apiId"],
        name="funcA",
        dataSourceName="noneDs",
        runtime=runtime,
        code=FUNC_A_CODE,
    )["functionConfiguration"]["functionId"]
    func_b = appsync.create_function(
        apiId=api["apiId"],
        name="funcB",
        dataSourceName="noneDs",
        runtime=runtime,
        code=FUNC_B_CODE,
    )["functionConfiguration"]["functionId"]

    appsync.create_resolver(
        apiId=api["apiId"],
        typeName="Query",
        fieldName="chainedCounter",
        kind="PIPELINE",
        pipelineConfig={"functions": [func_a, func_b]},
        runtime=runtime,
        code=_PIPELINE_TOP_CODE,
    )

    key = appsync.create_api_key(apiId=api["apiId"])["apiKey"]["id"]
    endpoint = api["uris"]["GRAPHQL"]
    body = _poll_graphql(ctx, endpoint, "query { chainedCounter }", api_key=key)
    assert body.get("errors") in (None, []), f"unexpected errors: {body.get('errors')}"
    assert body["data"]["chainedCounter"] == 11, (
        f"expected chainedCounter == 11 (0 -> +1 -> +10) after both pipeline functions ran, "
        f"got {body['data'].get('chainedCounter')!r}; full body={body}"
    )


_PIPELINE_TOP_CODE = (
    "export function request(ctx) {\n  ctx.stash.counter = 0;\n  return {};\n}\n"
    "export function response(ctx) {\n  return ctx.stash.counter;\n}\n"
)


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
        if status == 200 and last_body.get("data") is not None:
            return last_body
        time.sleep(2.0)
    raise AssertionError(f"graphql endpoint never returned data; last={last_body}")


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
