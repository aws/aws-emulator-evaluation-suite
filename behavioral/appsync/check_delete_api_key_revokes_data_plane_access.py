"""delete-api-key-revokes-data-plane-access."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-api-key-revokes-data-plane-access"
GROUP = "data-plane"
SERVICES = ["appsync"]

_SCHEMA = "type Query {\n  echo(message: String): String\n}\n"
_REQUEST_TEMPLATE = (
    '{\n  "version": "2018-05-29",\n  "payload": $util.toJson($context.arguments)\n}'
)
_RESPONSE_TEMPLATE = "$util.toJson($context.result.message)"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Deleting one API key immediately revokes that key's data-plane access while
    a second, still-valid key on the same API keeps working -- key revocation is
    per-key, not per-API."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    api_id = api["apiId"]
    key1 = _create_api_key(ctx, api_id)
    key2 = _create_api_key(ctx, api_id)
    url = api["uris"]["GRAPHQL"]

    _start_schema_and_wait(ctx, api_id, _SCHEMA)
    ds_name = _create_none_datasource(ctx, api_id)
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="echo",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate=_REQUEST_TEMPLATE,
        responseMappingTemplate=_RESPONSE_TEMPLATE,
    )

    query = "query Echo($msg: String) { echo(message: $msg) }"
    variables = {"msg": "still-valid"}

    def probe_key1():
        return _graphql_post(ctx, url, key1["id"], query, variables)

    status, body = _poll_until(
        probe_key1,
        lambda r: r[0] == 200 and r[1].get("data", {}).get("echo") == "still-valid",
        timeout_s=45.0,
        interval_s=3.0,
    )
    assert status == 200 and body["data"]["echo"] == "still-valid", (
        f"positive control for key1 never resolved: status={status} body={body!r}"
    )

    appsync.delete_api_key(apiId=api_id, id=key1["id"])

    remaining_ids = {k["id"] for k in appsync.list_api_keys(apiId=api_id)["apiKeys"]}
    assert key1["id"] not in remaining_ids, (
        f"deleted key1 still present in ListApiKeys: {sorted(remaining_ids)!r}"
    )
    assert key2["id"] in remaining_ids, (
        f"undeleted key2 missing from ListApiKeys: {sorted(remaining_ids)!r}"
    )

    status2, body2 = _poll_until(
        probe_key1,
        lambda r: r[0] == 401,
        timeout_s=45.0,
        interval_s=3.0,
    )
    assert status2 == 401, f"deleted key should be unauthorized, got {status2}: {body2}"
    assert body2.get("data") is None, (
        f"expected no resolved data for a revoked key, got {body2.get('data')!r}"
    )
    assert any(
        (e.get("errorType") or "") == "UnauthorizedException" for e in body2.get("errors", [])
    ), f"expected UnauthorizedException on the revoked key's response, got {body2!r}"

    status3, body3 = _graphql_post(ctx, url, key2["id"], query, {"msg": "second-key-ok"})
    assert status3 == 200 and body3["data"]["echo"] == "second-key-ok", (
        f"second, undeleted key should remain valid: {status3} {body3}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_graphql_api(ctx, auth_type="API_KEY"):
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType=auth_type,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api


def _create_api_key(ctx, api_id, expires=None):
    appsync = ctx.client("appsync")
    kwargs = {"apiId": api_id}
    if expires is not None:
        kwargs["expires"] = expires
    resp = appsync.create_api_key(**kwargs)
    key = resp["apiKey"]

    def _cleanup():
        try:
            appsync.delete_api_key(apiId=api_id, id=key["id"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return key


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


def _graphql_post(ctx, url, api_key, query, variables=None, timeout=15.0):
    body = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "x-api-key": api_key, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
