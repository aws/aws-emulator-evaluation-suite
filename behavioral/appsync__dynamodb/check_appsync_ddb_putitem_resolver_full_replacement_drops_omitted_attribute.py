"""appsync-ddb-putitem-resolver-full-replacement-drops-omitted-attribute."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import ssl
from typing import Any

from behavioral_harness import tags

CHECK = "appsync-ddb-putitem-resolver-full-replacement-drops-omitted-attribute"
GROUP = "overwrite-semantics"
SERVICES = ["appsync", "dynamodb", "iam"]

SCHEMA = """
type Item {
    id: String!
    a: String
    b: String
}
type Mutation {
    putItem(id: String!, a: String, b: String): Item
}
type Query {
    getItem(id: String!): Item
}
schema {
    query: Query
    mutation: Mutation
}
"""

PUT_REQUEST_TPL = """
#set($values = {})
#if($ctx.args.a)
$util.qr($values.put("a", $util.dynamodb.toDynamoDB($ctx.args.a)))
#end
#if($ctx.args.b)
$util.qr($values.put("b", $util.dynamodb.toDynamoDB($ctx.args.b)))
#end
{
  "version": "2017-02-28",
  "operation": "PutItem",
  "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.args.id) },
  "attributeValues": $util.toJson($values)
}
"""

GET_REQUEST_TPL = """
{
  "version": "2017-02-28",
  "operation": "GetItem",
  "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.args.id) }
}
"""

PASSTHROUGH_RESPONSE_TPL = "$util.toJson($ctx.result)"

MUTATION_PUT = """
mutation PutItem($id: String!, $a: String, $b: String) {
    putItem(id: $id, a: $a, b: $b) {
        id a b
    }
}
"""

QUERY_GET = """
query GetItem($id: String!) {
    getItem(id: $id) {
        id a b
    }
}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """A PutItem resolver with no update expression replaces the whole item: an attribute the
    second write omits is gone afterwards, not merely left unset in the mutation's own response.
    """
    table = _create_table(ctx)
    role_arn = _create_appsync_dynamodb_role(ctx, table["arn"])

    api = _create_graphql_api(ctx)
    api_key = _create_api_key(ctx, api["apiId"])
    _deploy_schema(ctx, api["apiId"], SCHEMA)
    ds_name = _create_dynamodb_datasource(ctx, api["apiId"], table["name"], role_arn)
    _create_unit_resolver(ctx, api["apiId"], "Mutation", "putItem", ds_name, PUT_REQUEST_TPL, PASSTHROUGH_RESPONSE_TPL)
    _create_unit_resolver(ctx, api["apiId"], "Query", "getItem", ds_name, GET_REQUEST_TPL, PASSTHROUGH_RESPONSE_TPL)

    headers = {"x-api-key": api_key}
    item_id = ctx.unique_name("item-")

    first = _request_past_role_propagation(
        ctx, lambda: _graphql_request(ctx, api["endpoint"], headers, MUTATION_PUT, {"id": item_id, "a": "alpha", "b": "beta"})
    )
    assert first is not None and not first.get("errors"), f"first putItem failed: {first}"
    first_item = first["data"]["putItem"]
    assert first_item == {"id": item_id, "a": "alpha", "b": "beta"}, (
        f"first putItem returned {first_item!r}, expected both attributes set"
    )

    second = _request_past_role_propagation(
        ctx, lambda: _graphql_request(ctx, api["endpoint"], headers, MUTATION_PUT, {"id": item_id, "a": "gamma"})
    )
    assert not second.get("errors"), f"second putItem failed: {second}"
    second_item = second["data"]["putItem"]
    assert second_item == {"id": item_id, "a": "gamma", "b": None}, (
        f"second putItem returned {second_item!r}, expected b dropped from its own response"
    )

    read_back = _request_past_role_propagation(
        ctx, lambda: _graphql_request(ctx, api["endpoint"], headers, QUERY_GET, {"id": item_id})
    )
    assert not read_back.get("errors"), f"getItem failed: {read_back}"
    stored = read_back["data"]["getItem"]
    assert stored == {"id": item_id, "a": "gamma", "b": None}, (
        f"a later independent read returned {stored!r}; the first write's 'b' attribute must be gone, "
        "not merely absent from the mutation's own echo"
    )


def _create_table(ctx: Any) -> dict[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-appsync-tbl-")
    resp = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
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
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:GetItem"], "Resource": table_arn}],
    }
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
