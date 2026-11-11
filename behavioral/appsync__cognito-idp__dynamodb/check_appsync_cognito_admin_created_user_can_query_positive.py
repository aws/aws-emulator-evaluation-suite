"""appsync-cognito-admin-created-user-can-query-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "appsync-cognito-admin-created-user-can-query-positive"
GROUP = "auth-boundary"
SERVICES = ["appsync", "cognito-idp", "dynamodb"]

SCHEMA_SDL = """type Item {
  id: String!
  value: String
}

type Query {
  getItem(id: String!): Item
}

type Mutation {
  putItem(id: String!, value: String!): Item
}

schema {
  query: Query
  mutation: Mutation
}
"""

REQUEST_GET = """{
  "version": "2017-02-28",
  "operation": "GetItem",
  "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.args.id) }
}"""

REQUEST_PUT = """{
  "version": "2017-02-28",
  "operation": "PutItem",
  "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.args.id) },
  "attributeValues": { "value": $util.dynamodb.toDynamoDBJson($ctx.args.value) }
}"""

RESPONSE_PASSTHROUGH = "$util.toJson($ctx.result)"


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A user provisioned via cognito-idp AdminCreateUser (temp password -> forced
    NEW_PASSWORD_REQUIRED challenge -> real sign-in) receives a token that successfully
    queries the AppSync API end-to-end."""
    pool_id, client_id = _create_user_pool_and_client(ctx)
    username = "sim2real-admincreated"
    tokens = _admin_created_user_tokens(ctx, pool_id, client_id, username, "Sim2Real!Temp1", "Sim2Real!Perm1")
    access_token = tokens["AccessToken"]

    stack = _build_appsync_stack(ctx, {
        "authenticationType": "AMAZON_COGNITO_USER_POOLS",
        "userPoolConfig": {"userPoolId": pool_id, "awsRegion": ctx.region, "defaultAction": "ALLOW"},
    })
    headers = {"Authorization": access_token}
    item_id = ctx.unique_name("item-")

    def _mutate():
        status, payload = _graphql_call(
            ctx, stack["url"],
            "mutation Put($id: String!, $value: String!) { putItem(id: $id, value: $value) { id } }",
            {"id": item_id, "value": "from-admin-created-user"},
            headers=headers,
        )
        assert status == 200 and not payload.get("errors"), f"mutation failed: {payload}"

    _retry(_mutate, timeout_s=45.0, interval_s=4.0)

    status, payload = _graphql_call(
        ctx, stack["url"],
        "query Get($id: String!) { getItem(id: $id) { id value } }",
        {"id": item_id},
        headers=headers,
    )
    assert status == 200 and not payload.get("errors"), f"query failed: {payload}"
    assert payload["data"]["getItem"]["value"] == "from-admin-created-user", (
        f"expected GraphQL query to return the written value, got {payload}"
    )

    ddb = ctx.client("dynamodb")
    item = ddb.get_item(TableName=stack["table_name"], Key={"id": {"S": item_id}})["Item"]
    assert item["value"]["S"] == "from-admin-created-user", (
        f"expected DynamoDB to hold the value written via AppSync, got {item}"
    )


def _create_user_pool_and_client(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real-check": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    return pool_id, client_id


def _admin_created_user_tokens(ctx, pool_id, client_id, username, temp_password, new_password):
    cognito = ctx.client("cognito-idp")
    cognito.admin_create_user(UserPoolId=pool_id, Username=username, TemporaryPassword=temp_password)
    resp = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": temp_password},
    )
    assert resp.get("ChallengeName") == "NEW_PASSWORD_REQUIRED", f"unexpected admin_initiate_auth response: {resp}"
    resp2 = cognito.admin_respond_to_auth_challenge(
        UserPoolId=pool_id,
        ClientId=client_id,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": new_password},
        Session=resp["Session"],
    )
    return resp2["AuthenticationResult"]


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]
    return table_name, table_arn


def _create_ds_role(ctx, table_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-pol-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:Scan"],
                "Resource": [table_arn, f"{table_arn}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _wait_for_schema(appsync, api_id, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status == "SUCCESS":
            return
        if status == "FAILED":
            raise AssertionError("schema creation failed")
        time.sleep(2)
    raise AssertionError("schema creation timed out")


def _retry(fn, timeout_s=30.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - eventual consistency (IAM propagation etc.)
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation did not succeed within {timeout_s}s: {last_exc}")


def _build_appsync_stack(ctx, auth_kwargs, schema_sdl=SCHEMA_SDL):
    appsync = ctx.client("appsync")
    api_name = ctx.unique_name("sim2real-api-")
    api = appsync.create_graphql_api(name=api_name, tags={"sim2real-check": CHECK}, **auth_kwargs)["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    appsync.start_schema_creation(apiId=api_id, definition=schema_sdl.encode("utf-8"))
    _wait_for_schema(appsync, api_id)

    table_name, table_arn = _create_table(ctx)
    role_arn = _create_ds_role(ctx, table_arn)
    ds_name = "DdbSource"
    _retry(
        lambda: appsync.create_data_source(
            apiId=api_id,
            name=ds_name,
            type="AMAZON_DYNAMODB",
            dynamodbConfig={"tableName": table_name, "awsRegion": ctx.region},
            serviceRoleArn=role_arn,
        ),
        timeout_s=30.0,
    )
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getItem",
        dataSourceName=ds_name,
        requestMappingTemplate=REQUEST_GET,
        responseMappingTemplate=RESPONSE_PASSTHROUGH,
    )
    appsync.create_resolver(
        apiId=api_id,
        typeName="Mutation",
        fieldName="putItem",
        dataSourceName=ds_name,
        requestMappingTemplate=REQUEST_PUT,
        responseMappingTemplate=RESPONSE_PASSTHROUGH,
    )
    return {"api_id": api_id, "url": api["uris"]["GRAPHQL"], "table_name": table_name, "appsync": appsync}


def _graphql_call(ctx, url, query, variables=None, headers=None, timeout_s=15.0):
    body = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(routed_url, data=body, headers={**req_headers, **route_headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = {"raw": raw}
        return exc.code, parsed


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
