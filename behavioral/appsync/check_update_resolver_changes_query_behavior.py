"""update-resolver-changes-query-behavior."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "update-resolver-changes-query-behavior"
GROUP = "data-plane"
SERVICES = ["appsync"]

SCHEMA_SDL = "type Query {\n  echo(msg: String): String\n}\n\nschema {\n  query: Query\n}\n"

ECHO_CODE = (
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
FIXED_CODE = (
    "export function request(ctx) {\n  return {};\n}\n"
    "export function response(ctx) {\n  return 'updated-value';\n}\n"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """UpdateResolver changes what a live GraphQL query returns, so the update reaches the
    query-execution path and not only the stored resolver record."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx, appsync)
    _create_schema(appsync, api["apiId"], SCHEMA_SDL)
    appsync.create_data_source(apiId=api["apiId"], name="noneDs", type="NONE")
    runtime = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
    appsync.create_resolver(
        apiId=api["apiId"],
        typeName="Query",
        fieldName="echo",
        kind="UNIT",
        dataSourceName="noneDs",
        runtime=runtime,
        code=ECHO_CODE,
    )
    key = appsync.create_api_key(apiId=api["apiId"])["apiKey"]["id"]
    endpoint = api["uris"]["GRAPHQL"]
    query = "query Echo($m: String) { echo(msg: $m) }"

    before = _poll_graphql(
        ctx, endpoint,
        query,
        api_key=key,
        variables={"m": "original"},
        # A freshly created resolver/API key can take a few seconds to propagate
        # through AppSync's data plane; immediately after creation a query can come
        # back HTTP 200 with `data` present but the field still null, so wait for the
        # actual expected value rather than merely "data is not None".
        expect=lambda b: b.get("data", {}).get("echo") == "original",
    )
    assert before["data"]["echo"] == "original", before

    appsync.update_resolver(
        apiId=api["apiId"],
        typeName="Query",
        fieldName="echo",
        kind="UNIT",
        dataSourceName="noneDs",
        runtime=runtime,
        code=FIXED_CODE,
    )

    after = _poll_graphql(
        ctx, endpoint,
        query,
        api_key=key,
        variables={"m": "original"},
        # UpdateResolver's new code has to propagate through AppSync's data-plane
        # compilation/caching layer before a live query observes it — verified against
        # real AWS: a query issued right after UpdateResolver can keep echoing the OLD
        # ("original") result well past the default 60s poll window, so give this
        # propagation-sensitive assertion a much larger allowance than the initial
        # (freshly-created, not-yet-serving-anything-else) resolver check above needed.
        timeout_s=180.0,
        expect=lambda b: b.get("data", {}).get("echo") == "updated-value",
    )
    assert after["data"]["echo"] == "updated-value", after


def _create_graphql_api(ctx, appsync):
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": "true"},
    )
    api = resp["graphqlApi"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api["apiId"]))
    return api


def _create_schema(appsync, api_id, sdl, timeout_s=90.0):
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
