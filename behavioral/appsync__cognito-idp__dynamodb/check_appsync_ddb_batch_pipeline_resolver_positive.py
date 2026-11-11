"""appsync-ddb-batch-pipeline-resolver-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "appsync-ddb-batch-pipeline-resolver-positive"
GROUP = "data-format"
SERVICES = ["appsync", "cognito-idp", "dynamodb"]

SCHEMA = """
input ItemInput {
    id: String!
    value: String!
}
type Item {
    id: String!
    value: String!
}
type Query {
    _placeholder: String
}
type Mutation {
    batchPutItems(items: [ItemInput!]!): [Item]
}
schema {
    query: Query
    mutation: Mutation
}
"""

FUNCTION_REQUEST_TPL = """
{
  "version": "2018-05-29",
  "operation": "BatchPutItem",
  "tables": {
    "__TABLE_NAME__": [
      #foreach($item in $ctx.args.items)
        $util.dynamodb.toMapValuesJson($item)
        #if($foreach.hasNext),#end
      #end
    ]
  }
}
"""

FUNCTION_RESPONSE_TPL = """
#if($ctx.error)
  $util.error($ctx.error.message, $ctx.error.type)
#end
$util.toJson($ctx.result.data["__TABLE_NAME__"])
"""

PIPELINE_BEFORE_TPL = "{}"
PIPELINE_AFTER_TPL = "$util.toJson($ctx.prev.result)"

MUTATION_BATCH_PUT = """
mutation BatchPut($items: [ItemInput!]!) {
    batchPutItems(items: $items) {
        id
        value
    }
}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """A pipeline resolver executes BatchPutItem and all items persist in one GraphQL call."""
    table = _create_table(
        ctx,
        [{"AttributeName": "id", "AttributeType": "S"}],
        [{"AttributeName": "id", "KeyType": "HASH"}],
    )
    role_arn = _create_appsync_dynamodb_role(ctx, [table["arn"]], ["dynamodb:BatchWriteItem"])
    api = _create_graphql_api(ctx)
    api_key = _create_api_key(ctx, api["apiId"])
    _deploy_schema(ctx, api["apiId"], SCHEMA)
    ds_name = _create_dynamodb_datasource(ctx, api["apiId"], table["name"], role_arn)

    request_tpl = FUNCTION_REQUEST_TPL.replace("__TABLE_NAME__", table["name"])
    response_tpl = FUNCTION_RESPONSE_TPL.replace("__TABLE_NAME__", table["name"])
    function_id = _create_function(ctx, api["apiId"], ds_name, request_tpl, response_tpl)
    _create_pipeline_resolver(ctx, api["apiId"], "Mutation", "batchPutItems", [function_id], PIPELINE_BEFORE_TPL, PIPELINE_AFTER_TPL)

    items = [{"id": ctx.unique_name(f"batch-{i}-"), "value": f"v{i}"} for i in range(5)]

    headers = {"x-api-key": api_key}
    resp = _poll_until(
        lambda: _graphql_request(ctx, api["endpoint"], headers, MUTATION_BATCH_PUT, {"items": items}),
        lambda r: not r.get("errors") and (r.get("data") or {}).get("batchPutItems"),
        timeout_s=45.0,
        description="batchPutItems mutation (data source IAM role propagation)",
    )
    assert not resp.get("errors"), f"batchPutItems mutation failed: {resp}"
    returned = resp["data"]["batchPutItems"]
    expected = sorted(items, key=lambda i: i["id"])
    actual = sorted(returned, key=lambda i: i["id"])
    assert actual == expected, f"batchPutItems response mismatch: expected {expected}, got {actual}"

    ddb = ctx.client("dynamodb")
    for item in items:
        stored = ddb.get_item(TableName=table["name"], Key={"id": {"S": item["id"]}})["Item"]
        assert stored["value"]["S"] == item["value"], (
            f"item {item['id']} not persisted correctly: expected value={item['value']!r}, "
            f"got item={stored!r}"
        )


def _create_table(ctx: Any, attribute_definitions, key_schema, gsi=None) -> dict[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-appsync-tbl-")
    kwargs: dict[str, Any] = dict(
        TableName=name,
        AttributeDefinitions=attribute_definitions,
        KeySchema=key_schema,
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resources}]}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline-policy", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-policy"))
    return role["Arn"]


def _create_graphql_api(ctx: Any, auth_type: str = "API_KEY", user_pool_config=None) -> dict[str, str]:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-appsync-api-")
    kwargs: dict[str, Any] = dict(name=name, authenticationType=auth_type, tags={"sim2real": CHECK})
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


def _create_function(ctx: Any, api_id: str, ds_name: str, req_tpl: str, resp_tpl: str) -> str:
    appsync = ctx.client("appsync")
    fn_name = _appsync_name(ctx, "sim2real_fn_")
    resp = appsync.create_function(
        apiId=api_id,
        name=fn_name,
        dataSourceName=ds_name,
        requestMappingTemplate=req_tpl,
        responseMappingTemplate=resp_tpl,
        functionVersion="2018-05-29",
    )
    function_id = resp["functionConfiguration"]["functionId"]
    ctx.on_cleanup(lambda: appsync.delete_function(apiId=api_id, functionId=function_id))
    return function_id


def _create_pipeline_resolver(ctx: Any, api_id: str, type_name: str, field_name: str, function_ids: list[str], before_tpl: str, after_tpl: str) -> None:
    appsync = ctx.client("appsync")
    appsync.create_resolver(
        apiId=api_id,
        typeName=type_name,
        fieldName=field_name,
        kind="PIPELINE",
        pipelineConfig={"functions": function_ids},
        requestMappingTemplate=before_tpl,
        responseMappingTemplate=after_tpl,
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
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
