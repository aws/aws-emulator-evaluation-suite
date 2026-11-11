"""appsync-apikey-expired-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "appsync-apikey-expired-negative"
GROUP = "overly-permissive"
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


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A GraphQL mutation with a no-longer-valid API key gets a 401 UnauthorizedException and writes
    nothing, while a still-valid key on the same API succeeds.
    """
    stack = _build_appsync_stack(ctx, {"authenticationType": "API_KEY"})
    appsync = stack["appsync"]

    valid_key = appsync.create_api_key(apiId=stack["api_id"], description="valid-control-key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: _safe_delete_key(appsync, stack["api_id"], valid_key))

    # API key expiry must be 1-365 days out, so a time-expired key cannot be produced in a run;
    # a deleted key fails the same key lookup and AppSync returns the same UnauthorizedException.
    invalidated_key = appsync.create_api_key(apiId=stack["api_id"], description="to-be-invalidated")["apiKey"]["id"]
    appsync.delete_api_key(apiId=stack["api_id"], id=invalidated_key)
    remaining_key_ids = {k["id"] for k in appsync.list_api_keys(apiId=stack["api_id"])["apiKeys"]}
    assert invalidated_key not in remaining_key_ids, (
        f"deleted key {invalidated_key} still present in ListApiKeys: {remaining_key_ids}"
    )

    ddb = ctx.client("dynamodb")
    good_item_id = ctx.unique_name("item-good-")

    def _mutate_with_valid_key():
        status, payload = _graphql_call(
            ctx, stack["url"],
            "mutation Put($id: String!, $value: String!) { putItem(id: $id, value: $value) { id } }",
            {"id": good_item_id, "value": "control-value"},
            headers={"x-api-key": valid_key},
        )
        assert status == 200 and not payload.get("errors"), f"positive control mutation failed: {payload}"

    _retry(_mutate_with_valid_key, timeout_s=45.0, interval_s=4.0)
    item = ddb.get_item(TableName=stack["table_name"], Key={"id": {"S": good_item_id}})["Item"]
    assert item["value"]["S"] == "control-value", f"expected the control write to persist, got {item}"

    # Key deletion propagates asynchronously: retry with a fresh item id until the key is refused.
    def _mutate_with_invalidated_key():
        item_id = ctx.unique_name("item-bad-")
        status, payload = _graphql_call(
            ctx, stack["url"],
            "mutation Put($id: String!, $value: String!) { putItem(id: $id, value: $value) { id } }",
            {"id": item_id, "value": "should-not-persist"},
            headers={"x-api-key": invalidated_key},
        )
        assert status == 401, f"expected 401 for a no-longer-valid API key, got {status}: {payload}"
        error_types = {e.get("errorType") for e in (payload.get("errors") or [])}
        assert "UnauthorizedException" in error_types, (
            f"expected UnauthorizedException for a no-longer-valid API key, got errors={payload.get('errors')}"
        )
        return item_id

    left = ctx.time_left()
    refusal_timeout_s = 60.0 if left is None else min(60.0, max(1.0, left - 5.0))
    bad_item_id = _retry(_mutate_with_invalidated_key, timeout_s=refusal_timeout_s, interval_s=2.0)
    get_resp = ddb.get_item(TableName=stack["table_name"], Key={"id": {"S": bad_item_id}})
    assert "Item" not in get_resp, f"item was written despite a no-longer-valid API key: {get_resp}"


def _safe_delete_key(appsync, api_id, key_id):
    try:
        appsync.delete_api_key(apiId=api_id, id=key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": "appsync-apikey-expired-negative"}],
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
        Tags=[{"Key": "sim2real-check", "Value": "appsync-apikey-expired-negative"}],
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
        except Exception as exc:  # noqa: BLE001 - eventual consistency (IAM/key propagation etc.)
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation did not succeed within {timeout_s}s: {last_exc}")


def _build_appsync_stack(ctx, auth_kwargs, schema_sdl=SCHEMA_SDL):
    appsync = ctx.client("appsync")
    api_name = ctx.unique_name("sim2real-api-")
    api = appsync.create_graphql_api(
        name=api_name,
        tags={"sim2real-check": "appsync-apikey-expired-negative"},
        **auth_kwargs,
    )["graphqlApi"]
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
