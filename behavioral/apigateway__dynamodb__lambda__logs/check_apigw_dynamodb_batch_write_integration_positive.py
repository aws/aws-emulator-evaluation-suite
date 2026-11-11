"""apigw-dynamodb-batch-write-integration-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "apigw-dynamodb-batch-write-integration-positive"
GROUP = "resource-binding"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_REQUEST_TEMPLATE_BATCH = """{
  "RequestItems": {
    "__TABLE__": [
#foreach($item in $input.path('$.items'))
      {"PutRequest": {"Item": {"id": {"S": "$item.id"}, "value": {"S": "$item.value"}}}}#if($foreach.hasNext),#end
#end
    ]
  }
}"""


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AWS-integration mapped to dynamodb:BatchWriteItem persists multiple items from one API call."""
    table = _create_table(
        ctx,
        [{"AttributeName": "id", "KeyType": "HASH"}],
        [{"AttributeName": "id", "AttributeType": "S"}],
    )
    role_arn = _create_apigw_role(ctx, table["arn"], ["dynamodb:BatchWriteItem"])
    api_id, root_id = _create_rest_api(ctx)
    template = _REQUEST_TEMPLATE_BATCH.replace("__TABLE__", table["name"])
    resource_id = _add_dynamodb_method(
        ctx, api_id, root_id, "batch", "POST", "BatchWriteItem", role_arn,
        template, [("200", None, None)], ["200"],
    )

    id_a = ctx.unique_name("sim2real-batch-a-")
    id_b = ctx.unique_name("sim2real-batch-b-")
    id_c = ctx.unique_name("sim2real-batch-c-")
    body = json.dumps(
        {
            "items": [
                {"id": id_a, "value": "one"},
                {"id": id_b, "value": "two"},
                {"id": id_c, "value": "three"},
            ]
        }
    )

    result = _poll_until(
        lambda: _invoke(ctx, api_id, resource_id, "POST", body),
        lambda r: r["status"] == 200,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert result["status"] == 200, result["body"]

    ddb = ctx.client("dynamodb")
    got_a = ddb.get_item(TableName=table["name"], Key={"id": {"S": id_a}})
    got_b = ddb.get_item(TableName=table["name"], Key={"id": {"S": id_b}})
    got_c = ddb.get_item(TableName=table["name"], Key={"id": {"S": id_c}})
    assert "Item" in got_a, f"batch item {id_a!r} was not written by the API Gateway integration"
    assert "Item" in got_b, f"batch item {id_b!r} was not written by the API Gateway integration"
    assert "Item" in got_c, f"batch item {id_c!r} was not written by the API Gateway integration"
    assert got_a["Item"]["value"]["S"] == "one", got_a["Item"]["value"]["S"]
    assert got_b["Item"]["value"]["S"] == "two", got_b["Item"]["value"]["S"]
    assert got_c["Item"]["value"]["S"] == "three", got_c["Item"]["value"]["S"]


def _uname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"sim2real-apigwddb-{kind}-")


def _create_table(ctx, key_schema, attr_defs) -> dict[str, str]:
    ddb = ctx.client("dynamodb")
    name = _uname(ctx, "tbl")
    ddb.create_table(
        TableName=name,
        KeySchema=key_schema,
        AttributeDefinitions=attr_defs,
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return {"name": name, "arn": arn}


def _create_apigw_role(ctx, resource_arn: str, actions: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = _uname(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "apigateway.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if actions:
        policy_name = _uname(ctx, "policy")
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource_arn}],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_rest_api(ctx) -> tuple[str, str]:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=_uname(ctx, "api"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    return api_id, root_id


def _add_dynamodb_method(
    ctx,
    api_id: str,
    parent_id: str,
    path_part: str,
    http_method: str,
    action: str,
    role_arn: str,
    request_template: str,
    integration_responses: list[tuple[str, str | None, str | None]],
    method_status_codes: list[str],
) -> str:
    apigw = ctx.client("apigateway")
    resource_id = apigw.create_resource(restApiId=api_id, parentId=parent_id, pathPart=path_part)["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, authorizationType="NONE")
    uri = f"arn:aws:apigateway:{ctx.region}:dynamodb:action/{action}"
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        type="AWS",
        integrationHttpMethod="POST",
        uri=uri,
        credentials=role_arn,
        requestTemplates={"application/json": request_template},
        passthroughBehavior="NEVER",
    )
    for status_code, selection_pattern, resp_template in integration_responses:
        kwargs: dict[str, Any] = dict(
            restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode=status_code,
        )
        if selection_pattern is not None:
            kwargs["selectionPattern"] = selection_pattern
        if resp_template is not None:
            kwargs["responseTemplates"] = {"application/json": resp_template}
        apigw.put_integration_response(**kwargs)
    for status_code in method_status_codes:
        apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode=status_code)
    return resource_id


def _invoke(ctx, api_id: str, resource_id: str, http_method: str, body: str) -> dict[str, Any]:
    apigw = ctx.client("apigateway")
    resp = apigw.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        body=body,
        headers={"Content-Type": "application/json"},
    )
    return {"status": resp["status"], "body": resp["body"]}


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
