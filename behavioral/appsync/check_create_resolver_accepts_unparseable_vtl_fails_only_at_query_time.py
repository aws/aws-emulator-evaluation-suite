"""create-resolver-accepts-unparseable-vtl-fails-only-at-query-time."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-resolver-accepts-unparseable-vtl-fails-only-at-query-time"
GROUP = "data-plane"
SERVICES = ["appsync"]

_SCHEMA = "type Query {\n  good: String\n  bad: String\n}\n"
_GOOD_RESPONSE = "$util.toJson($util.math.roundNum(1.6))"
# Unterminated #if directive: EvaluateMappingTemplate rejects it synchronously, but
# CreateResolver performs no static VTL validation.
_BAD_RESPONSE = "#if($context.arguments.id"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """CreateResolver accepts a response template with an unterminated #if; the query then returns a
    MappingTemplate error with null data for that field while a sibling resolver still resolves.
    """
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    api_id = api["apiId"]
    api_key = _create_api_key(ctx, api_id)["id"]
    url = api["uris"]["GRAPHQL"]

    _start_schema_and_wait(ctx, api_id, _SCHEMA)
    ds_name = _create_none_datasource(ctx, api_id)

    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="good",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate='{"version": "2018-05-29", "payload": {}}',
        responseMappingTemplate=_GOOD_RESPONSE,
    )
    ctx.on_cleanup(
        lambda: appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="good")
    )

    # Creating the deliberately broken resolver succeeding is the first half of the claim.
    create_resp = appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="bad",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate='{"version": "2018-05-29", "payload": {}}',
        responseMappingTemplate=_BAD_RESPONSE,
    )
    assert create_resp["resolver"]["fieldName"] == "bad", (
        f"CreateResolver with unparseable VTL unexpectedly returned: {create_resp!r}"
    )
    ctx.on_cleanup(
        lambda: appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="bad")
    )

    query = "query { good bad }"

    def probe():
        return _graphql_post(ctx, url, api_key, query)

    status, body = _poll_until(
        probe,
        lambda r: r[0] == 200 and (r[1].get("data", {}).get("good") is not None or r[1].get("errors")),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert status == 200, f"expected HTTP 200 envelope even with a failing field: {status} {body!r}"

    assert body.get("data", {}).get("good") == "2", (
        f"positive control (good) must still resolve beside the broken sibling: {body!r}"
    )

    errors = body.get("errors") or []
    assert len(errors) == 1, f"expected exactly one GraphQL error for the broken field: {body!r}"
    assert errors[0]["path"] == ["bad"], f"error attributed to the wrong field: {errors[0]!r}"
    assert errors[0]["errorType"] == "MappingTemplate", (
        f"expected errorType=='MappingTemplate' for a VTL parse failure, got {errors[0]!r}"
    )
    assert body["data"].get("bad") is None, (
        f"the broken field's data must be absent (null), not a partial/garbage value: {body!r}"
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
        name=ctx.unique_name("sim2real-behav-"), authenticationType=auth_type
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
