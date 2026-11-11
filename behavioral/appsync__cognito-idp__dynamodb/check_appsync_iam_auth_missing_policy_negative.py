"""appsync-iam-auth-missing-policy-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import botocore.auth
import botocore.awsrequest
import botocore.credentials

from behavioral_harness import tags

CHECK = "appsync-iam-auth-missing-policy-negative"
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


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """On an AWS_IAM API, a role without an appsync:GraphQL grant gets 401 and writes nothing, a
    sibling role with the grant succeeds, and granting the statement to the denied role makes the
    same call succeed, so the missing statement is the cause of the denial."""
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    stack = _build_appsync_stack(ctx, {"authenticationType": "AWS_IAM"})
    api_arn = f"arn:aws:appsync:{ctx.region}:{account_id}:apis/{stack['api_id']}/*"

    allowed_creds = _create_assumable_role(ctx, account_id, allow_graphql=True, api_arn=api_arn)
    denied_role_name, denied_creds = _create_assumable_role(
        ctx, account_id, allow_graphql=False, api_arn=api_arn, return_role_name=True
    )

    ddb = ctx.client("dynamodb")
    good_item_id = ctx.unique_name("item-good-")
    bad_item_id = ctx.unique_name("item-bad-")

    def _mutate_allowed():
        status, payload = _graphql_call_iam(
            ctx, stack["url"],
            "mutation Put($id: String!, $value: String!) { putItem(id: $id, value: $value) { id } }",
            {"id": good_item_id, "value": "control-value"},
            allowed_creds,
            ctx.region,
        )
        assert status == 200 and not payload.get("errors"), f"positive control mutation failed: {payload}"

    _retry(_mutate_allowed, timeout_s=60.0, interval_s=5.0)
    item = ddb.get_item(TableName=stack["table_name"], Key={"id": {"S": good_item_id}})["Item"]
    assert item["value"]["S"] == "control-value", (
        f"positive-control write must be readable back verbatim via an independent DynamoDB read, "
        f"got {item!r}"
    )

    def _mutate_denied():
        return _graphql_call_iam(
            ctx, stack["url"],
            "mutation Put($id: String!, $value: String!) { putItem(id: $id, value: $value) { id } }",
            {"id": bad_item_id, "value": "should-not-persist"},
            denied_creds,
            ctx.region,
        )

    status, payload = _mutate_denied()
    assert status == 401, f"expected 401 for a principal lacking appsync:GraphQL, got {status}: {payload}"
    absent = ddb.get_item(TableName=stack["table_name"], Key={"id": {"S": bad_item_id}})
    assert "Item" not in absent, f"item was written despite the denied principal lacking appsync:GraphQL: {absent}"

    # Restore: grant the SAME denied role the missing statement and re-issue the IDENTICAL call.
    # This is what turns "this principal happened to be denied" into "the missing appsync:GraphQL
    # statement was the cause" -- without it, a target that denies every AWS_IAM call regardless of
    # policy would pass just as easily as one that actually evaluates the identity policy.
    iam = ctx.client("iam")
    restore_policy_name = ctx.unique_name("sim2real-graphql-restore-pol-")
    iam.put_role_policy(
        RoleName=denied_role_name,
        PolicyName=restore_policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["appsync:GraphQL"], "Resource": [api_arn]}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=denied_role_name, PolicyName=restore_policy_name))

    sts = ctx.client("sts")
    denied_role_arn = f"arn:aws:iam::{account_id}:role/{denied_role_name}"

    def _mutate_restored():
        fresh = sts.assume_role(RoleArn=denied_role_arn, RoleSessionName=ctx.unique_name("sess-restore-"))["Credentials"]
        status2, payload2 = _graphql_call_iam(
            ctx, stack["url"],
            "mutation Put($id: String!, $value: String!) { putItem(id: $id, value: $value) { id } }",
            {"id": bad_item_id, "value": "should-not-persist"},
            fresh,
            ctx.region,
        )
        assert status2 == 200 and not payload2.get("errors"), (
            f"expected the identical call to succeed once the missing appsync:GraphQL statement "
            f"was granted to the same role (fresh session), got {status2}: {payload2}"
        )

    _retry(_mutate_restored, timeout_s=60.0, interval_s=5.0)
    restored = ddb.get_item(TableName=stack["table_name"], Key={"id": {"S": bad_item_id}})["Item"]
    assert restored["value"]["S"] == "should-not-persist", (
        f"the restored principal's write must now be visible via an independent DynamoDB read, "
        f"got {restored!r}"
    )


def _create_assumable_role(ctx, account_id, allow_graphql, api_arn, return_role_name=False):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    role_name = ctx.unique_name("sim2real-caller-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "appsync-iam-auth-missing-policy-negative"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if allow_graphql:
        policy_name = ctx.unique_name("sim2real-graphql-pol-")
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["appsync:GraphQL"], "Resource": [api_arn]}],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    def _assume():
        return sts.assume_role(RoleArn=role_arn, RoleSessionName=ctx.unique_name("sess-"))["Credentials"]

    creds = _retry(_assume, timeout_s=40.0, interval_s=3.0)
    return (role_name, creds) if return_role_name else creds


def _sigv4_headers(creds, region, service, method, url, body):
    frozen = botocore.credentials.Credentials(
        creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"]
    )
    request = botocore.awsrequest.AWSRequest(method=method, url=url, data=body, headers={"Content-Type": "application/json"})
    botocore.auth.SigV4Auth(frozen, service, region).add_auth(request)
    return dict(request.headers.items())


def _graphql_call_iam(ctx, url, query, variables, creds, region, timeout_s=15.0):
    body = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    headers = _sigv4_headers(creds, region, "appsync", "POST", url, body)
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(routed_url, data=body, headers={**headers, **route_headers}, method="POST")
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


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": "appsync-iam-auth-missing-policy-negative"}],
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
        Tags=[{"Key": "sim2real", "Value": "appsync-iam-auth-missing-policy-negative"}],
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
    api = appsync.create_graphql_api(
        name=api_name, tags={"sim2real": "appsync-iam-auth-missing-policy-negative"}, **auth_kwargs
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
