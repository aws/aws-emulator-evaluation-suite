"""cli-appsync-apikey-query-ddb-positive."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "cli-appsync-apikey-query-ddb-positive"
GROUP = "cli-roundtrip"
SERVICES = ["appsync", "cognito-idp", "dynamodb"]

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-widgets"},
]
_TAGS_CLI = "sim2real:managed=true,sim2real:prefix=sim2real-widgets"

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


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An API key created via `aws` CLI authorizes a GraphQL query that reads an item which
    was written directly to DynamoDB (bypassing AppSync entirely), proving the resolver's
    read path against real data rather than data it wrote itself."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    ddb = ctx.client("dynamodb")
    table_name, table_arn = _create_ddb_table(ctx)
    ddb.put_item(TableName=table_name, Item={"id": {"S": "w-read"}, "name": {"S": "DirectWrite"}})

    role_arn = _iam_role_for_appsync_ddb(ctx, table_arn)
    api_id, endpoint = _create_graphql_api_cli(ctx, "API_KEY")
    _create_schema_cli(ctx, api_id)
    ds_name = _create_datasource_cli(ctx, api_id, table_name, role_arn)
    _create_resolvers_cli(ctx, api_id, ds_name)
    api_key = _create_api_key_cli(ctx, api_id)

    query = "query Get($id: ID!) { getWidget(id: $id) { id name } }"
    body = _graphql_call_with_retry(ctx, endpoint, query, {"id": "w-read"}, headers={"x-api-key": api_key})
    assert body["data"]["getWidget"] == {"id": "w-read", "name": "DirectWrite"}, body


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
        Tags=_TAGS_KV,
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS_KV,
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


def _create_graphql_api_cli(ctx, auth_type, user_pool_id=None):
    name = ctx.unique_name("sim2real-appsync-")
    args = [
        "appsync", "create-graphql-api", "--name", name, "--authentication-type", auth_type,
        "--tags", _TAGS_CLI,
    ]
    if user_pool_id:
        cfg = json.dumps({"userPoolId": user_pool_id, "awsRegion": ctx.region, "defaultAction": "ALLOW"})
        args += ["--user-pool-config", cfg]
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
    ds_name = "WidgetsDataSource"
    ds_cfg = json.dumps({"tableName": table_name, "awsRegion": ctx.region})
    deadline = time.monotonic() + timeout_s
    cmd = [
        "aws", "--output", "json", "appsync", "create-data-source",
        "--api-id", api_id, "--name", ds_name, "--type", "AMAZON_DYNAMODB",
        "--dynamodb-config", ds_cfg, "--service-role-arn", role_arn,
    ]
    last_err = None
    while time.monotonic() < deadline:
        proc = _run_shell(ctx, cmd, timeout_s=30.0, check=False)
        if proc.returncode == 0:
            return ds_name
        last_err = proc.stderr[-500:]
        # Only an unassumable-role refusal is IAM propagation; any other failure is real.
        if role_arn not in proc.stderr and "assume" not in proc.stderr.lower():
            raise AssertionError(f"create-data-source failed (rc={proc.returncode}): {last_err}")
        time.sleep(interval_s)
    raise AssertionError(
        f"create-data-source never succeeded waiting for IAM role propagation: {last_err}"
    )


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


def _create_api_key_cli(ctx, api_id):
    result = _run_aws(ctx, "appsync", "create-api-key", "--api-id", api_id, "--description", "sim2real-test-key")
    return result["apiKey"]["id"]


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
