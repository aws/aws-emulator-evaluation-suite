"""appsync-invalid-api-key-rejected."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "appsync-invalid-api-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync", "cognito-idp", "dynamodb"]

SCHEMA = """
type Item {
    id: String!
    value: String!
}
type Query {
    _placeholder: String
}
type Mutation {
    putItem(id: String!, value: String!): Item
}
schema {
    query: Query
    mutation: Mutation
}
"""

PUT_REQUEST_TPL = """
{
  "version": "2017-02-28",
  "operation": "PutItem",
  "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.args.id) },
  "attributeValues": { "value": $util.dynamodb.toDynamoDBJson($ctx.args.value) }
}
"""

PASSTHROUGH_RESPONSE_TPL = "$util.toJson($ctx.result)"

MUTATION_PUT = """
mutation PutItem($id: String!, $value: String!) {
    putItem(id: $id, value: $value) {
        id
        value
    }
}
"""


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """An API_KEY-authenticated GraphQL API rejects a request bearing a bogus x-api-key with no
    data-plane effect; the identical request with the real key (positive control) succeeds."""
    table = _create_table(
        ctx,
        [{"AttributeName": "id", "AttributeType": "S"}],
        [{"AttributeName": "id", "KeyType": "HASH"}],
    )
    role_arn = _create_appsync_dynamodb_role(ctx, [table["arn"]], ["dynamodb:PutItem"])
    api = _create_graphql_api(ctx)
    real_api_key = _create_api_key(ctx, api["apiId"])
    _deploy_schema(ctx, api["apiId"], SCHEMA)
    ds_name = _create_dynamodb_datasource(ctx, api["apiId"], table["name"], role_arn)
    _create_unit_resolver(ctx, api["apiId"], "Mutation", "putItem", ds_name, PUT_REQUEST_TPL, PASSTHROUGH_RESPONSE_TPL)

    item_id = ctx.unique_name("item-")
    variables = {"id": item_id, "value": "hello"}
    bogus_key = real_api_key[:-4] + ("0" * 4 if real_api_key[-4:] != "0000" else "1111")

    resp = _graphql_request(ctx, api["endpoint"], {"x-api-key": bogus_key}, MUTATION_PUT, variables)
    assert resp.get("errors"), f"expected a rejection, got: {resp}"
    error_type = resp["errors"][0]["errorType"]
    assert error_type == "UnauthorizedException", f"expected UnauthorizedException, got: {error_type!r} ({resp})"

    ddb = ctx.client("dynamodb")
    get_resp = ddb.get_item(TableName=table["name"], Key={"id": {"S": item_id}})
    assert "Item" not in get_resp, f"item was written despite an invalid api key: {get_resp}"

    # Positive control: identical call, real key.
    resp2 = _poll_until(
        lambda: _graphql_request(ctx, api["endpoint"], {"x-api-key": real_api_key}, MUTATION_PUT, variables),
        lambda r: not r.get("errors") and (r.get("data") or {}).get("putItem"),
        timeout_s=45.0,
        description="putItem succeeding with the real api key",
    )
    assert resp2 is not None and not resp2.get("errors"), f"putItem failed with the real api key: {resp2}"
    put_result = resp2["data"]["putItem"]
    assert put_result == {"id": item_id, "value": "hello"}, f"expected {{'id': {item_id!r}, 'value': 'hello'}}, got: {put_result}"

    item = ddb.get_item(TableName=table["name"], Key={"id": {"S": item_id}})["Item"]
    assert item["value"]["S"] == "hello", f"expected DynamoDB item value 'hello', got: {item['value']}"


def _create_table(ctx: Any, attribute_definitions, key_schema, gsi=None) -> dict[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-appsync-tbl-")
    kwargs: dict[str, Any] = dict(
        TableName=name,
        AttributeDefinitions=attribute_definitions,
        KeySchema=key_schema,
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    if gsi:
        kwargs["GlobalSecondaryIndexes"] = gsi
    resp = ddb.create_table(**kwargs)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return {"name": name, "arn": resp["TableDescription"]["TableArn"]}


def _create_appsync_dynamodb_role(ctx: Any, resources: list[str], actions: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-appsync-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resources}]}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline-policy", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-policy"))
    return role["Arn"]


def _create_graphql_api(ctx: Any, auth_type: str = "API_KEY", user_pool_config=None) -> dict[str, str]:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-appsync-api-")
    kwargs: dict[str, Any] = dict(
        name=name,
        authenticationType=auth_type,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    if user_pool_config:
        kwargs["userPoolConfig"] = user_pool_config
    resp = appsync.create_graphql_api(**kwargs)
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


def _create_unit_resolver(ctx: Any, api_id: str, type_name: str, field_name: str, ds_name: str, req_tpl: str, resp_tpl: str) -> None:
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


def _graphql_request(ctx, endpoint: str, headers: dict[str, str], query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
    body = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    routed_url, route_headers = ctx.endpoint_route(endpoint)
    req = urllib.request.Request(routed_url, data=body, method="POST", headers=route_headers)
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode("utf-8"))


def _poll_until(probe, predicate, timeout_s: float = 45.0, interval_s: float = 3.0, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last result: {result}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
