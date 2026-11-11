"""pipeline-resolver-update-reorders-execution."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pipeline-resolver-update-reorders-execution"
GROUP = "data-plane"
SERVICES = ["appsync"]

_SCHEMA = "type Query {\n  pipelineOrder: Int\n}\n"

_SET_TEN_REQ = '#set($ctx.stash.value = 10)\n{"version":"2018-05-29","payload":{}}'
_ADD_FIVE_REQ = (
    '#set($ctx.stash.value = $util.defaultIfNull($ctx.stash.value, 0) + 5)\n'
    '{"version":"2018-05-29","payload":{}}'
)
_PASSTHROUGH_RESP = "$util.toJson($ctx.result)"
_BEFORE_TEMPLATE = '{"version":"2018-05-29","payload":{}}'
_AFTER_TEMPLATE = "$util.toJson($ctx.stash.value)"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """UpdateResolver reordering a PIPELINE resolver's function list changes the
    actual execution order (and thus the real GraphQL result) -- pipelineConfig.functions
    order is a live semantic, not a cosmetic field."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    api_id = api["apiId"]
    api_key = _create_api_key(ctx, api_id)["id"]
    url = api["uris"]["GRAPHQL"]

    _start_schema_and_wait(ctx, api_id, _SCHEMA)
    ds_name = _create_none_datasource(ctx, api_id)

    set_ten = appsync.create_function(
        apiId=api_id,
        name=ctx.unique_name("sim2real_setten_").replace("-", "_"),
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate=_SET_TEN_REQ,
        responseMappingTemplate=_PASSTHROUGH_RESP,
    )["functionConfiguration"]["functionId"]

    add_five = appsync.create_function(
        apiId=api_id,
        name=ctx.unique_name("sim2real_addfive_").replace("-", "_"),
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate=_ADD_FIVE_REQ,
        responseMappingTemplate=_PASSTHROUGH_RESP,
    )["functionConfiguration"]["functionId"]

    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="pipelineOrder",
        kind="PIPELINE",
        pipelineConfig={"functions": [set_ten, add_five]},
        requestMappingTemplate=_BEFORE_TEMPLATE,
        responseMappingTemplate=_AFTER_TEMPLATE,
    )

    query = "query { pipelineOrder }"

    def probe():
        return _graphql_post(ctx, url, api_key, query)

    status, body = _poll_until(
        probe,
        lambda r: r[0] == 200 and r[1].get("data", {}).get("pipelineOrder") == 15,
        timeout_s=45.0,
        interval_s=3.0,
    )
    assert status == 200 and not body.get("errors"), (
        f"expected a clean 200 GraphQL response before any update, got status={status!r} "
        f"body={body!r}"
    )
    assert body["data"]["pipelineOrder"] == 15, "set(10) then +5 must yield 15"

    appsync.update_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="pipelineOrder",
        kind="PIPELINE",
        pipelineConfig={"functions": [add_five, set_ten]},
        requestMappingTemplate=_BEFORE_TEMPLATE,
        responseMappingTemplate=_AFTER_TEMPLATE,
    )

    # UpdateResolver's pipelineConfig re-ordering needs a bit longer than the initial
    # create to actually propagate to the data plane; give it a wider bounded window
    # than the first poll (which observes the just-created resolver's steady state).
    status2, body2 = _poll_until(
        probe,
        lambda r: r[0] == 200 and r[1].get("data", {}).get("pipelineOrder") == 10,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert status2 == 200 and not body2.get("errors"), (
        f"expected a clean 200 GraphQL response after reordering the pipeline, got "
        f"status={status2!r} body={body2!r}"
    )
    assert body2["data"]["pipelineOrder"] == 10, "+5(on null->0) then set(10) must yield 10"


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
