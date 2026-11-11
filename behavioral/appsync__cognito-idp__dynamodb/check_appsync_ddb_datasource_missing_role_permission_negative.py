"""appsync-ddb-datasource-missing-role-permission-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "appsync-ddb-datasource-missing-role-permission-negative"
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


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """A data source role lacking dynamodb:PutItem makes the resolver fail with no item written;
    granting the permission (positive control) makes the identical call succeed."""
    table = _create_table(
        ctx,
        [{"AttributeName": "id", "AttributeType": "S"}],
        [{"AttributeName": "id", "KeyType": "HASH"}],
    )
    # Role deliberately grants only GetItem -- PutItem is withheld.
    role_name, role_arn = _create_appsync_dynamodb_role(ctx, [table["arn"]], ["dynamodb:GetItem"])

    api = _create_graphql_api(ctx)
    api_key = _create_api_key(ctx, api["apiId"])
    _deploy_schema(ctx, api["apiId"], SCHEMA)
    ds_name = _create_dynamodb_datasource(ctx, api["apiId"], table["name"], role_arn)
    _create_unit_resolver(ctx, api["apiId"], "Mutation", "putItem", ds_name, PUT_REQUEST_TPL, PASSTHROUGH_RESPONSE_TPL)

    headers = {"x-api-key": api_key}
    item_id = ctx.unique_name("item-")
    variables = {"id": item_id, "value": "hello"}

    ddb = ctx.client("dynamodb")

    # Wait until the request reaches DynamoDB (ruling out transient IAM-role-not-yet-usable noise),
    # then pin the exact rejection.
    # The IAM role was just created; AppSync may transiently fail to assume it until the
    # role/policy change propagates ("Unable to assume role..."). Keep polling past that
    # transient error and only stop once we see a definitive (non-role-assumption) rejection.
    def _is_definitive_rejection(r: dict[str, Any]) -> bool:
        errors = r.get("errors") or []
        if not errors:
            return False
        message = errors[0].get("message", "")
        return "unable to assume role" not in message.lower()

    resp = _poll_until(
        lambda: _graphql_request(ctx, api["endpoint"], headers, MUTATION_PUT, variables),
        _is_definitive_rejection,
        timeout_s=60.0,
        interval_s=4.0,
    )
    assert resp is not None and resp.get("errors"), f"expected a rejection, got: {resp}"
    first_error = resp["errors"][0]
    error_type = first_error.get("errorType", "")
    error_message = first_error.get("message", "")
    assert "AccessDenied" in error_type or "AccessDenied" in error_message or "not authorized" in error_message.lower(), (
        f"expected an access-denied rejection, got: {first_error}"
    )
    assert (resp.get("data") or {}).get("putItem") is None, (
        f"expected no putItem data on a denied mutation, got: {resp.get('data')}"
    )

    get_resp = ddb.get_item(TableName=table["name"], Key={"id": {"S": item_id}})
    assert "Item" not in get_resp, f"item was written despite missing permission: {get_resp}"

    # Positive control: grant the missing permission and retry the identical call.
    iam = ctx.client("iam")
    fixed_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:PutItem"], "Resource": [table["arn"]]}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="inline-policy", PolicyDocument=json.dumps(fixed_policy))

    resp2 = _poll_until(
        lambda: _graphql_request(ctx, api["endpoint"], headers, MUTATION_PUT, variables),
        lambda r: not r.get("errors") and (r.get("data") or {}).get("putItem"),
        timeout_s=45.0,
    )
    assert resp2 is not None and not resp2.get("errors"), f"putItem still failing after permission fix: {resp2}"
    assert resp2["data"]["putItem"] == {"id": item_id, "value": "hello"}, (
        f"expected putItem to echo {{'id': {item_id!r}, 'value': 'hello'}}, got: {resp2['data'].get('putItem')}"
    )

    item = ddb.get_item(TableName=table["name"], Key={"id": {"S": item_id}})["Item"]
    assert item["value"]["S"] == "hello", f"expected persisted value 'hello', got: {item['value']}"


def _create_table(ctx: Any, attribute_definitions, key_schema, gsi=None) -> dict[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-appsync-tbl-")
    kwargs: dict[str, Any] = dict(
        TableName=name,
        AttributeDefinitions=attribute_definitions,
        KeySchema=key_schema,
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": "appsync-ddb-datasource-missing-role-permission-negative"}],
    )
    if gsi:
        kwargs["GlobalSecondaryIndexes"] = gsi
    resp = ddb.create_table(**kwargs)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return {"name": name, "arn": resp["TableDescription"]["TableArn"]}


def _create_appsync_dynamodb_role(ctx: Any, resources: list[str], actions: list[str]) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-appsync-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "appsync-ddb-datasource-missing-role-permission-negative"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resources}]}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline-policy", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-policy"))
    return role_name, role["Arn"]


def _create_graphql_api(ctx: Any, auth_type: str = "API_KEY", user_pool_config=None) -> dict[str, str]:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-appsync-api-")
    kwargs: dict[str, Any] = dict(
        name=name,
        authenticationType=auth_type,
        tags={"sim2real": "appsync-ddb-datasource-missing-role-permission-negative"},
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


def _poll_until(probe, predicate, timeout_s: float = 45.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last probe result: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
