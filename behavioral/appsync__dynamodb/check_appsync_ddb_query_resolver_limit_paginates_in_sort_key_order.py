"""appsync-ddb-query-resolver-limit-paginates-in-sort-key-order."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "appsync-ddb-query-resolver-limit-paginates-in-sort-key-order"
GROUP = "query-pagination"
SERVICES = ["appsync", "dynamodb", "iam"]

SCHEMA = """
type Item {
    pk: String!
    sk: String!
}
type ItemPage {
    items: [Item]
    nextToken: String
}
type Query {
    listItems(pk: String!, limit: Int, nextToken: String): ItemPage
}
schema {
    query: Query
}
"""

QUERY_REQUEST_TPL = """
{
  "version": "2017-02-28",
  "operation": "Query",
  "query": {
    "expression": "pk = :pk",
    "expressionValues": { ":pk": $util.dynamodb.toDynamoDBJson($ctx.args.pk) }
  },
  "limit": $util.defaultIfNull($ctx.args.limit, 20),
  "nextToken": $util.toJson($util.defaultIfNullOrBlank($ctx.args.nextToken, null))
}
"""

RESPONSE_TPL = """
{
  "items": $util.toJson($ctx.result.items),
  "nextToken": $util.toJson($ctx.result.nextToken)
}
"""

QUERY_LIST = """
query ListItems($pk: String!, $limit: Int, $nextToken: String) {
    listItems(pk: $pk, limit: $limit, nextToken: $nextToken) {
        items { pk sk }
        nextToken
    }
}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """A DynamoDB Query resolver's `limit` bounds each page to the exact count requested, in
    ascending sort-key order, and the final page under the limit carries a null nextToken.
    """
    table = _create_table(ctx)
    ddb = ctx.client("dynamodb")
    pk = ctx.unique_name("pk-")
    sort_keys = [f"item-{i:04d}" for i in range(1, 6)]  # 5 items: 0001..0005
    for sk in sort_keys:
        ddb.put_item(TableName=table["name"], Item={"pk": {"S": pk}, "sk": {"S": sk}})

    api = _create_graphql_api(ctx)
    api_key = _create_api_key(ctx, api["apiId"])
    _deploy_schema(ctx, api["apiId"], SCHEMA)
    role_arn = _create_appsync_dynamodb_role(ctx, table["arn"])
    ds_name = _create_dynamodb_datasource(ctx, api["apiId"], table["name"], role_arn)
    _create_unit_resolver(ctx, api["apiId"], "Query", "listItems", ds_name, QUERY_REQUEST_TPL, RESPONSE_TPL)

    headers = {"x-api-key": api_key}

    page1 = _request_past_role_propagation(
        ctx, lambda: _graphql_request(ctx, api["endpoint"], headers, QUERY_LIST, {"pk": pk, "limit": 2})
    )
    assert page1 is not None and not page1.get("errors"), f"first page query failed: {page1}"
    listing1 = page1["data"]["listItems"]
    page1_sks = [i["sk"] for i in listing1["items"]]
    assert page1_sks == sort_keys[0:2], f"page 1 returned {page1_sks!r}, expected {sort_keys[0:2]!r}"
    assert listing1["nextToken"] is not None, "page 1 under the full count must carry a nextToken"

    page2 = _request_past_role_propagation(
        ctx,
        lambda: _graphql_request(
            ctx, api["endpoint"], headers, QUERY_LIST, {"pk": pk, "limit": 2, "nextToken": listing1["nextToken"]}
        ),
    )
    assert not page2.get("errors"), f"second page query failed: {page2}"
    listing2 = page2["data"]["listItems"]
    page2_sks = [i["sk"] for i in listing2["items"]]
    assert page2_sks == sort_keys[2:4], f"page 2 returned {page2_sks!r}, expected {sort_keys[2:4]!r}"
    assert listing2["nextToken"] is not None, "page 2 under the full count must carry a nextToken"

    page3 = _request_past_role_propagation(
        ctx,
        lambda: _graphql_request(
            ctx, api["endpoint"], headers, QUERY_LIST, {"pk": pk, "limit": 2, "nextToken": listing2["nextToken"]}
        ),
    )
    assert not page3.get("errors"), f"third page query failed: {page3}"
    listing3 = page3["data"]["listItems"]
    page3_sks = [i["sk"] for i in listing3["items"]]
    assert page3_sks == sort_keys[4:5], f"page 3 returned {page3_sks!r}, expected {sort_keys[4:5]!r}"
    assert listing3["nextToken"] is None, (
        f"the last page, holding fewer items than the limit, carried nextToken {listing3['nextToken']!r}"
    )


def _create_table(ctx: Any) -> dict[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-appsync-tbl-")
    resp = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return {"name": name, "arn": resp["TableDescription"]["TableArn"]}


def _create_appsync_dynamodb_role(ctx: Any, table_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-appsync-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["dynamodb:Query"], "Resource": table_arn}]}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline-policy", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-policy"))
    return role["Arn"]


def _create_graphql_api(ctx: Any) -> dict[str, str]:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-appsync-api-")
    resp = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return {"apiId": api_id, "endpoint": api["uris"]["GRAPHQL"]}


def _create_api_key(ctx: Any, api_id: str) -> str:
    appsync = ctx.client("appsync")
    return appsync.create_api_key(apiId=api_id)["apiKey"]["id"]


def _deploy_schema(ctx: Any, api_id: str, sdl: str, timeout_s: float = 60.0) -> None:
    appsync = ctx.client("appsync")
    appsync.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)
        if status["status"] == "SUCCESS":
            return
        if status["status"] == "FAILED":
            raise AssertionError(f"schema creation failed: {status.get('details')}")
        time.sleep(2)
    raise AssertionError(f"schema creation timed out: {status}")


def _appsync_name(ctx: Any, prefix: str) -> str:
    return ctx.unique_name(prefix).replace("-", "_")


def _create_dynamodb_datasource(ctx: Any, api_id: str, table_name: str, role_arn: str) -> str:
    appsync = ctx.client("appsync")
    ds_name = _appsync_name(ctx, "sim2real_ds_")
    appsync.create_data_source(
        apiId=api_id,
        name=ds_name,
        type="AMAZON_DYNAMODB",
        serviceRoleArn=role_arn,
        dynamodbConfig={"tableName": table_name, "awsRegion": ctx.region},
    )
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))
    return ds_name


def _create_unit_resolver(
    ctx: Any, api_id: str, type_name: str, field_name: str, ds_name: str, req_tpl: str, resp_tpl: str
) -> None:
    appsync = ctx.client("appsync")
    appsync.create_resolver(
        apiId=api_id,
        typeName=type_name,
        fieldName=field_name,
        dataSourceName=ds_name,
        requestMappingTemplate=req_tpl,
        responseMappingTemplate=resp_tpl,
    )
    ctx.on_cleanup(lambda: appsync.delete_resolver(apiId=api_id, typeName=type_name, fieldName=field_name))


def _graphql_request(
    ctx: Any, endpoint: str, headers: dict[str, str], query: str, variables: dict[str, Any] | None = None
) -> dict[str, Any]:
    body = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    routed_url, route_headers = ctx.endpoint_route(endpoint)
    req = urllib.request.Request(routed_url, data=body, method="POST", headers=route_headers)
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=20, context=_ssl_context(ctx.http_verify)) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read())


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _request_past_role_propagation(ctx: Any, send, *, timeout_s: float = 45.0, interval_s: float = 2.0):
    """Retry ``send()`` while its only error is the service role's permission not yet propagated."""
    propagating = (
        "is not authorized to perform",
        "Unable to assume role",
        "The security token included in the request is invalid",
    )
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = send()
        errors = result.get("errors") or []
        message = errors[0].get("message", "") if errors else ""
        if not errors or not any(p in message for p in propagating):
            return result
        time.sleep(interval_s)
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
