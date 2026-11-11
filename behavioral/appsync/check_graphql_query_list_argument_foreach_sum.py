"""graphql-query-list-argument-foreach-sum."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "graphql-query-list-argument-foreach-sum"
GROUP = "data-plane"
SERVICES = ["appsync"]

_SCHEMA = "type Query {\n  sumList(nums: [Int]): Int\n}\n"
_REQUEST_TEMPLATE = (
    "#set($sum = 0)\n"
    "#foreach($n in $context.arguments.nums)\n"
    "#set($sum = $sum + $n)\n"
    "#end\n"
    '{\n  "version": "2018-05-29",\n  "payload": { "sum": $sum }\n}'
)
_RESPONSE_TEMPLATE = "$util.toJson($context.result.sum)"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A VTL #foreach loop over a real GraphQL list argument accumulates a sum on
    the live data plane -- exercising loop control flow and arithmetic, not just
    field passthrough."""
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
        fieldName="sumList",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate=_REQUEST_TEMPLATE,
        responseMappingTemplate=_RESPONSE_TEMPLATE,
    )

    query = "query Sum($nums: [Int]) { sumList(nums: $nums) }"
    variables = {"nums": [1, 2, 3, 4]}

    def probe():
        return _graphql_post(ctx, url, api_key, query, variables)

    status, body = _poll_until(
        probe,
        lambda r: r[0] == 200 and r[1].get("data", {}).get("sumList") == 10,
        timeout_s=45.0,
        interval_s=3.0,
    )
    assert status == 200 and not body.get("errors"), body
    assert body["data"]["sumList"] == 10, (
        f"expected VTL #foreach sum over {variables['nums']} == 10, "
        f"got {body.get('data', {}).get('sumList')!r} (body={body!r})"
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
