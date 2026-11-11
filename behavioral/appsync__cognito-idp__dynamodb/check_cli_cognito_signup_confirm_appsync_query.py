"""cli-cognito-signup-confirm-appsync-query."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-cognito-signup-confirm-appsync-query"
GROUP = "sdk-cli-interop"
SERVICES = ["appsync", "cognito-idp", "dynamodb"]

_SCHEMA_SDL = """
type Widget {
  id: ID!
  name: String
}
type Query {
  getWidget(id: ID!): Widget
}
type Mutation {
  putWidget(id: ID!, name: String!): Widget
}
schema {
  query: Query
  mutation: Mutation
}
""".strip()

_REQUEST_GET = """{
  "version": "2017-02-28",
  "operation": "GetItem",
  "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.args.id) }
}"""

_REQUEST_PUT = """{
  "version": "2017-02-28",
  "operation": "PutItem",
  "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.args.id) },
  "attributeValues": { "name": $util.dynamodb.toDynamoDBJson($ctx.args.name) }
}"""

_RESPONSE_PASSTHROUGH = "$util.toJson($ctx.result)"


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A user who self-signs-up and is confirmed entirely through cognito-idp CLI commands
    obtains an ID token that successfully authorizes an AppSync query reading an item that
    was written directly to DynamoDB (bypassing AppSync) beforehand."""
    require_tools("aws")

    ddb = ctx.client("dynamodb")
    table_name, table_arn = _create_ddb_table(ctx)
    ddb.put_item(TableName=table_name, Item={"id": {"S": "seed"}, "name": {"S": "SeededValue"}})

    role_arn = _iam_role_for_appsync_ddb(ctx, table_arn)
    pool_id, client_id = _create_user_pool_cli(ctx)
    api_id, endpoint = _create_graphql_api_cli(ctx, "AMAZON_COGNITO_USER_POOLS", user_pool_id=pool_id)
    _create_schema_cli(ctx, api_id)
    ds_name = _create_datasource_cli(ctx, api_id, table_name, role_arn)
    _create_resolvers_cli(ctx, api_id, ds_name)

    username = ctx.unique_name("sim2real-user-")
    password = "TestPass123"
    _sign_up_and_confirm_cli(ctx, pool_id, client_id, username, password)
    token = _initiate_auth_user_password_cli(ctx, client_id, username, password)

    query = "query Get($id: ID!) { getWidget(id: $id) { id name } }"
    body = _graphql_call_with_retry(ctx, endpoint, query, {"id": "seed"}, headers={"Authorization": token})
    assert body["data"]["getWidget"] == {"id": "seed", "name": "SeededValue"}, body


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["AWS_PAGER"] = ""
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _create_ddb_table(ctx):
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-widgets-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]
    return table_name, table_arn


def _iam_role_for_appsync_ddb(ctx, table_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-appsync-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"],
            "Resource": [table_arn, f"{table_arn}/index/*"],
        }],
    }
    policy_name = ctx.unique_name("sim2real-appsync-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _create_user_pool_cli(ctx):
    name = ctx.unique_name("sim2real-pool-")
    policies = json.dumps({
        "PasswordPolicy": {
            "MinimumLength": 8, "RequireUppercase": False, "RequireLowercase": True,
            "RequireNumbers": True, "RequireSymbols": False,
        }
    })
    tags = json.dumps({"sim2real": CHECK})
    result = _run_aws(
        ctx, "cognito-idp", "create-user-pool", "--pool-name", name,
        "--policies", policies, "--user-pool-tags", tags,
    )
    pool_id = result["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "cognito-idp", "delete-user-pool", "--user-pool-id", pool_id, check=False))
    client_result = _run_aws(
        ctx, "cognito-idp", "create-user-pool-client", "--user-pool-id", pool_id,
        "--client-name", ctx.unique_name("sim2real-client-"),
        "--explicit-auth-flows", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH",
        "--no-generate-secret",
    )
    client_id = client_result["UserPoolClient"]["ClientId"]
    return pool_id, client_id


def _create_graphql_api_cli(ctx, auth_type, user_pool_id=None):
    name = ctx.unique_name("sim2real-appsync-")
    args = ["appsync", "create-graphql-api", "--name", name, "--authentication-type", auth_type]
    if user_pool_id:
        cfg = json.dumps({"userPoolId": user_pool_id, "awsRegion": ctx.region, "defaultAction": "ALLOW"})
        args += ["--user-pool-config", cfg]
    args += ["--tags", json.dumps({"sim2real": CHECK})]
    result = _run_aws(ctx, *args)
    api_id = result["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "appsync", "delete-graphql-api", "--api-id", api_id, check=False))
    endpoint = result["graphqlApi"]["uris"]["GRAPHQL"]
    return api_id, endpoint


def _create_schema_cli(ctx, api_id, timeout_s=90.0):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".graphql", delete=False) as f:
        f.write(_SCHEMA_SDL)
        schema_path = f.name
    try:
        _run_shell(ctx, ["aws", "appsync", "start-schema-creation", "--api-id", api_id, "--definition", f"fileb://{schema_path}"])
    finally:
        os.unlink(schema_path)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = _run_aws(ctx, "appsync", "get-schema-creation-status", "--api-id", api_id)["status"]
        if status == "SUCCESS":
            return
        if status == "FAILED":
            raise AssertionError("schema creation failed")
        time.sleep(2)
    raise AssertionError("schema creation did not reach SUCCESS in time")


def _create_datasource_cli(ctx, api_id, table_name, role_arn, timeout_s=30.0, interval_s=3.0):
    """CreateDataSource is where AppSync first tries to assume the service role, so this is
    where IAM role/policy propagation lag actually surfaces -- retry on it with a deadline
    rather than sleeping blindly beforehand."""
    ds_name = "WidgetsDataSource"
    ds_cfg = json.dumps({"tableName": table_name, "awsRegion": ctx.region})
    deadline = time.monotonic() + timeout_s
    last_stderr = None
    while True:
        proc = _run_shell(
            ctx,
            ["aws", "--output", "json", "appsync", "create-data-source",
             "--api-id", api_id, "--name", ds_name, "--type", "AMAZON_DYNAMODB",
             "--dynamodb-config", ds_cfg, "--service-role-arn", role_arn],
            check=False,
        )
        if proc.returncode == 0:
            return ds_name
        last_stderr = proc.stderr
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"create-data-source did not succeed within {timeout_s}s "
                f"(rc={proc.returncode}): {last_stderr[-500:]}"
            )
        time.sleep(interval_s)


def _create_resolvers_cli(ctx, api_id, ds_name):
    _run_aws(
        ctx, "appsync", "create-resolver",
        "--api-id", api_id, "--type-name", "Query", "--field-name", "getWidget",
        "--data-source-name", ds_name,
        "--request-mapping-template", _REQUEST_GET,
        "--response-mapping-template", _RESPONSE_PASSTHROUGH,
    )
    _run_aws(
        ctx, "appsync", "create-resolver",
        "--api-id", api_id, "--type-name", "Mutation", "--field-name", "putWidget",
        "--data-source-name", ds_name,
        "--request-mapping-template", _REQUEST_PUT,
        "--response-mapping-template", _RESPONSE_PASSTHROUGH,
    )


def _sign_up_and_confirm_cli(ctx, pool_id, client_id, username, password):
    _run_aws(ctx, "cognito-idp", "sign-up", "--client-id", client_id, "--username", username, "--password", password)
    _run_aws(ctx, "cognito-idp", "admin-confirm-sign-up", "--user-pool-id", pool_id, "--username", username)


def _initiate_auth_user_password_cli(ctx, client_id, username, password):
    result = _run_aws(
        ctx, "cognito-idp", "initiate-auth", "--client-id", client_id,
        "--auth-flow", "USER_PASSWORD_AUTH",
        "--auth-parameters", json.dumps({"USERNAME": username, "PASSWORD": password}),
    )
    return result["AuthenticationResult"]["IdToken"]


def _graphql_request(ctx, endpoint, query, variables=None, headers=None, timeout_s=15.0):
    payload = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    routed_url, route_headers = ctx.endpoint_route(endpoint)
    req = urllib.request.Request(routed_url, data=payload, headers={**req_headers, **route_headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return json.loads(resp.read().decode("utf-8")), resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return json.loads(raw), exc.code
        except (json.JSONDecodeError, ValueError):
            return {"raw": raw}, exc.code


def _graphql_call_with_retry(ctx, endpoint, query, variables, headers, timeout_s=45.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        body, status = _graphql_request(ctx, endpoint, query, variables, headers)
        if status == 200 and not body.get("errors"):
            return body
        last = (status, body)
        time.sleep(interval_s)
    raise AssertionError(f"GraphQL call never returned a clean response: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
