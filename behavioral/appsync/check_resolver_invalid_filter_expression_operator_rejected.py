"""resolver-invalid-filter-expression-operator-rejected."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "resolver-invalid-filter-expression-operator-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]

_SCHEMA = (
    "type Query {\n"
    "  badFilter(token: String!): AWSJSON\n"
    "  goodFilter(token: String!): AWSJSON\n"
    "}\n"
)
_REQUEST_TEMPLATE = '{\n  "version": "2018-05-29",\n  "payload": {}\n}'
_BAD_RESPONSE_TEMPLATE = (
    '$util.toJson($util.transform.toDynamoDBFilterExpression('
    '{"status":{"bogusOperator":$context.arguments.token}}))'
)
_GOOD_RESPONSE_TEMPLATE = (
    '$util.toJson($util.transform.toDynamoDBFilterExpression('
    '{"status":{"contains":$context.arguments.token}}))'
)


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """$util.transform.toDynamoDBFilterExpression with an undefined operator fails the
    field at query time with an exact error; a sibling resolver using a documented
    operator on the same API still serves its field.

    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/transformation-helpers-in-utils-transform.html
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
        fieldName="badFilter",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate=_REQUEST_TEMPLATE,
        responseMappingTemplate=_BAD_RESPONSE_TEMPLATE,
    )
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="goodFilter",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate=_REQUEST_TEMPLATE,
        responseMappingTemplate=_GOOD_RESPONSE_TEMPLATE,
    )

    token = ctx.unique_name("sim2real-filter-probe-")
    query = (
        "query Probe($token: String!) {\n"
        "  badFilter(token: $token)\n"
        "  goodFilter(token: $token)\n"
        "}"
    )
    status, body = _graphql_post(ctx, url, api_key, query, {"token": token})
    assert status == 200, f"unexpected HTTP status: {status}, body={body}"

    errors = body.get("errors") or []
    bad_errors = [e for e in errors if e.get("path") == ["badFilter"]]
    assert len(bad_errors) == 1, f"expected exactly one error for badFilter, got {errors!r}"
    error = bad_errors[0]
    assert error["errorType"] == "DynamoDBFilterError", f"unexpected errorType: {error['errorType']!r}"
    assert error["message"] == (
        "Error generating DynamoDB filter expression from input - "
        f"{{status={{bogusOperator={token}}}}}"
    ), f"unexpected message: {error['message']!r}"
    assert body["data"]["badFilter"] is None, f"expected null data for badFilter, got {body['data']['badFilter']!r}"

    good_filter_json = (
        '{"expression":"(contains(#status,:status_contains))",'
        '"expressionNames":{"#status":"status"},'
        f'"expressionValues":{{":status_contains":{{"S":"{token}"}}}}}}'
    )
    expected_good = json.dumps(good_filter_json)
    assert body["data"]["goodFilter"] == expected_good, (
        f"positive control: expected {expected_good!r}, got {body['data']['goodFilter']!r}"
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
