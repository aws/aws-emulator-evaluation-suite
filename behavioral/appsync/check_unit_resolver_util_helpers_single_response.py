"""unit-resolver-util-helpers-single-response."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "unit-resolver-util-helpers-single-response"
GROUP = "data-plane"
SERVICES = ["appsync"]

_SCHEMA = (
    "type Query {\n"
    "  probe(token: String!): Probe\n"
    "}\n"
    "type Probe {\n"
    "  str: String\n"
    "  math: Float\n"
    "  list: AWSJSON\n"
    "  map: AWSJSON\n"
    "  dynamodb: AWSJSON\n"
    "  filter: AWSJSON\n"
    "  epoch: Int\n"
    "}\n"
)
_REQUEST_TEMPLATE = '{\n  "version": "2018-05-29",\n  "payload": {}\n}'
_RESPONSE_TEMPLATE = (
    '#set($result = {})\n'
    '$util.qr($result.put("str", $util.str.toReplace("hello world", "hello", "mellow")))\n'
    '$util.qr($result.put("math", $util.math.maxVal(3.5, 7.25)))\n'
    '$util.qr($result.put("list", $util.list.copyAndRetainAll(["red","green","blue"], ["green","blue"])))\n'
    '$util.qr($result.put("map", $util.map.copyAndRetainAllKeys({"a":1,"b":2,"c":3}, ["b","c"])))\n'
    '$util.qr($result.put("dynamodb", $util.dynamodb.toDynamoDB($context.arguments.token)))\n'
    '$util.qr($result.put("filter", $util.transform.toDynamoDBFilterExpression({"status":{"eq":$context.arguments.token}})))\n'
    '$util.qr($result.put("epoch", $util.time.nowEpochSeconds()))\n'
    '$util.toJson($result)'
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A NONE-datasource UNIT resolver's request/response VTL computes every $util helper
    in a single live GraphQL response: str, math, list, map, dynamodb, a DynamoDB filter
    expression, and an epoch-seconds clock reading.

    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/resolver-util-reference.html
    """
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    url = api["uris"]["GRAPHQL"]

    key = appsync.create_api_key(apiId=api_id)["apiKey"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=key["id"]))
    api_key = key["id"]

    _start_schema_and_wait(appsync, api_id, _SCHEMA)

    ds_name = ctx.unique_name("sim2real_ds_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")

    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="probe",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate=_REQUEST_TEMPLATE,
        responseMappingTemplate=_RESPONSE_TEMPLATE,
    )

    token = ctx.unique_name("sim2real-util-probe-")
    query = (
        "query Probe($token: String!) {\n"
        "  probe(token: $token) { str math list map dynamodb filter epoch }\n"
        "}"
    )
    before = time.time()
    status, body = _graphql_post(ctx, url, api_key, query, {"token": token})
    after = time.time()
    assert status == 200, f"unexpected HTTP status: {status}, body={body}"
    assert not body.get("errors"), f"unexpected GraphQL errors: {body.get('errors')}"
    probe = body["data"]["probe"]

    assert probe["str"] == "mellow world", f"$util.str.toReplace: got {probe['str']!r}"
    assert probe["math"] == 7.25, f"$util.math.maxVal: got {probe['math']!r}"

    # AWSJSON fields carry a Map or List helper's result as compact JSON text, not a
    # nested GraphQL object.
    assert probe["list"] == '["green","blue"]', (
        f"$util.list.copyAndRetainAll: got {probe['list']!r}"
    )
    assert probe["map"] == '{"b":2,"c":3}', f"$util.map.copyAndRetainAllKeys: got {probe['map']!r}"
    assert probe["dynamodb"] == json.dumps({"S": token}, separators=(",", ":")), (
        f"$util.dynamodb.toDynamoDB: got {probe['dynamodb']!r}"
    )

    # $util.transform.toDynamoDBFilterExpression is put into the result map already
    # rendered as a JSON string (via Map.put), so the AWSJSON field carries that string
    # JSON-encoded a second time: a quoted, escaped string, not a nested object.
    filter_json = (
        '{"expression":"(#status = :status_eq)",'
        '"expressionNames":{"#status":"status"},'
        f'"expressionValues":{{":status_eq":{{"S":"{token}"}}}}}}'
    )
    expected_filter = json.dumps(filter_json)
    assert probe["filter"] == expected_filter, (
        f"$util.transform.toDynamoDBFilterExpression: got {probe['filter']!r}"
    )

    epoch = probe["epoch"]
    assert isinstance(epoch, int), f"$util.time.nowEpochSeconds: expected an int, got {epoch!r}"
    assert before - 300 <= epoch <= after + 300, (
        f"$util.time.nowEpochSeconds: {epoch} not within 300s of the caller's clock "
        f"[{before!r}, {after!r}]"
    )


def _start_schema_and_wait(appsync, api_id, definition, timeout_s=120.0, interval_s=3.0):
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
