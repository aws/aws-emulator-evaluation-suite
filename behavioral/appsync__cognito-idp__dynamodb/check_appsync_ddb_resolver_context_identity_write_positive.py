"""appsync-ddb-resolver-context-identity-write-positive."""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "appsync-ddb-resolver-context-identity-write-positive"
GROUP = "data-format"
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
    putMyItem(value: String!): Item
}
schema {
    query: Query
    mutation: Mutation
}
"""

PUT_MY_ITEM_REQUEST_TPL = """
{
  "version": "2017-02-28",
  "operation": "PutItem",
  "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.identity.sub) },
  "attributeValues": { "value": $util.dynamodb.toDynamoDBJson($ctx.args.value) }
}
"""

PASSTHROUGH_RESPONSE_TPL = "$util.toJson($ctx.result)"

MUTATION_PUT_MY_ITEM = """
mutation PutMyItem($value: String!) {
    putMyItem(value: $value) {
        id
        value
    }
}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """A Cognito-authenticated caller's $context.identity.sub is used by the resolver as the
    DynamoDB partition key -- never supplied by the client as a GraphQL argument."""
    table = _create_table(
        ctx,
        [{"AttributeName": "id", "AttributeType": "S"}],
        [{"AttributeName": "id", "KeyType": "HASH"}],
    )
    role_arn = _create_appsync_dynamodb_role(ctx, [table["arn"]], ["dynamodb:PutItem"])

    user_pool_id, client_id = _create_user_pool_with_client(ctx)
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real-Passw0rd!23"
    _create_confirmed_user(ctx, user_pool_id, username, password)
    id_token = _sign_in(ctx, client_id, username, password)
    sub = _decode_jwt_claims(id_token)["sub"]

    api = _create_graphql_api(
        ctx,
        auth_type="AMAZON_COGNITO_USER_POOLS",
        user_pool_config={"userPoolId": user_pool_id, "awsRegion": ctx.region, "defaultAction": "ALLOW"},
    )
    _deploy_schema(ctx, api["apiId"], SCHEMA)
    ds_name = _create_dynamodb_datasource(ctx, api["apiId"], table["name"], role_arn)
    _create_unit_resolver(ctx, api["apiId"], "Mutation", "putMyItem", ds_name, PUT_MY_ITEM_REQUEST_TPL, PASSTHROUGH_RESPONSE_TPL)

    headers = {"Authorization": id_token}
    resp = _poll_until(
        lambda: _graphql_request(ctx, api["endpoint"], headers, MUTATION_PUT_MY_ITEM, {"value": "identity-write"}),
        lambda r: not r.get("errors") and (r.get("data") or {}).get("putMyItem"),
        timeout_s=45.0,
        description="putMyItem mutation succeeded",
    )
    assert resp["data"]["putMyItem"] == {"id": sub, "value": "identity-write"}, (
        f"expected putMyItem to echo the caller's identity.sub as id: "
        f"expected {{'id': {sub!r}, 'value': 'identity-write'}}, got {resp['data']['putMyItem']!r}"
    )

    ddb = ctx.client("dynamodb")
    item = ddb.get_item(TableName=table["name"], Key={"id": {"S": sub}}).get("Item")
    assert item is not None, f"expected an item keyed by identity.sub={sub!r} in {table['name']}, found none"
    assert item["value"]["S"] == "identity-write", (
        f"expected DynamoDB item at id={sub!r} (written via $ctx.identity.sub) to have value='identity-write', "
        f"got {item['value']['S']!r}"
    )

    scanned = ddb.scan(TableName=table["name"])["Items"]
    assert len(scanned) == 1, (
        f"expected exactly one item in {table['name']} keyed by the caller's identity.sub, "
        f"found {len(scanned)}: {scanned!r}"
    )


def _create_table(ctx: Any, attribute_definitions, key_schema, gsi=None) -> dict[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-appsync-tbl-")
    kwargs: dict[str, Any] = dict(
        TableName=name,
        AttributeDefinitions=attribute_definitions,
        KeySchema=key_schema,
        BillingMode="PAY_PER_REQUEST",
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resources}]}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline-policy", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-policy"))
    return role["Arn"]


def _create_graphql_api(ctx: Any, auth_type: str = "API_KEY", user_pool_config=None) -> dict[str, str]:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-appsync-api-")
    kwargs: dict[str, Any] = dict(name=name, authenticationType=auth_type)
    if user_pool_config:
        kwargs["userPoolConfig"] = user_pool_config
    resp = appsync.create_graphql_api(**kwargs)
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return {"apiId": api_id, "endpoint": api["uris"]["GRAPHQL"]}


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


def _create_user_pool_with_client(ctx: Any) -> tuple[str, str]:
    cognito = ctx.client("cognito-idp")
    pool_name = ctx.unique_name("sim2real-pool-")
    pool_id = cognito.create_user_pool(PoolName=pool_name)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]
    return pool_id, client["ClientId"]


def _create_confirmed_user(ctx: Any, user_pool_id: str, username: str, password: str) -> None:
    cognito = ctx.client("cognito-idp")
    cognito.admin_create_user(
        UserPoolId=user_pool_id, Username=username, TemporaryPassword="Tmp-" + password, MessageAction="SUPPRESS"
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=user_pool_id, Username=username))
    cognito.admin_set_user_password(UserPoolId=user_pool_id, Username=username, Password=password, Permanent=True)


def _sign_in(ctx: Any, client_id: str, username: str, password: str) -> str:
    cognito = ctx.client("cognito-idp")
    resp = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]["IdToken"]


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    payload_b64 = token.split(".")[1]
    padding = "=" * (-len(payload_b64) % 4)
    payload_json = base64.urlsafe_b64decode(payload_b64 + padding)
    return json.loads(payload_json)


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


def _poll_until(probe, predicate, *, timeout_s: float = 45.0, interval_s: float = 3.0, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
