"""deploy-appsync-multi-datasource-pipeline-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-appsync-multi-datasource-pipeline-positive"
GROUP = "data-format"
SERVICES = ["appsync", "cognito-idp", "dynamodb"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A pipeline resolver spanning two DynamoDB data sources runs both functions in order and
    the top-level response mapping aggregates their stashed results correctly."""
    orders_table = _xname(ctx, "orders")
    audit_table = _xname(ctx, "audit")
    role_name = _xname(ctx, "role")
    api_name = _xname(ctx, "api")
    orders_ds = _alnum_name(ctx, "orders_ds")
    audit_ds = _alnum_name(ctx, "audit_ds")
    fn1_name = _alnum_name(ctx, "fn_order")
    fn2_name = _alnum_name(ctx, "fn_audit")

    schema = (
        "schema { query: Query mutation: Mutation }\n"
        "type Query { noop: String }\n"
        "type Mutation { createOrderWithAudit(item: String!): OrderResult }\n"
        "type OrderResult { orderId: ID! auditId: ID! }\n"
    )

    fn1_request_tpl = (
        "#set($orderId = $util.autoId())\n"
        "#set($ctx.stash.orderId = $orderId)\n"
        "{\n"
        '  "version": "2018-05-29",\n'
        '  "operation": "PutItem",\n'
        '  "key": { "orderId": $util.dynamodb.toDynamoDBJson($orderId) },\n'
        '  "attributeValues": { "item": $util.dynamodb.toDynamoDBJson($ctx.args.item) }\n'
        "}"
    )
    fn2_request_tpl = (
        "#set($auditId = $util.autoId())\n"
        "#set($ctx.stash.auditId = $auditId)\n"
        "{\n"
        '  "version": "2018-05-29",\n'
        '  "operation": "PutItem",\n'
        '  "key": { "auditId": $util.dynamodb.toDynamoDBJson($auditId) },\n'
        '  "attributeValues": {\n'
        '    "orderId": $util.dynamodb.toDynamoDBJson($ctx.stash.orderId),\n'
        '    "action": $util.dynamodb.toDynamoDBJson("CREATE")\n'
        "  }\n"
        "}"
    )
    fn_response_tpl = (
        "#if($ctx.error)\n  $util.error($ctx.error.message, $ctx.error.type)\n#end\n"
        "$util.toJson($ctx.result)"
    )
    pipeline_before_tpl = "{}"
    pipeline_after_tpl = (
        "{\n"
        '  "orderId": $util.toJson($ctx.stash.orderId),\n'
        '  "auditId": $util.toJson($ctx.stash.auditId)\n'
        "}"
    )

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "OrdersTable": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": orders_table,
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "orderId", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "orderId", "KeyType": "HASH"}],
                },
            },
            "AuditTable": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": audit_table,
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "auditId", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "auditId", "KeyType": "HASH"}],
                },
            },
            "PipelineRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "appsync.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "ddb-access",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
                                        "Resource": [
                                            {"Fn::GetAtt": ["OrdersTable", "Arn"]},
                                            {"Fn::GetAtt": ["AuditTable", "Arn"]},
                                        ],
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "GraphQLApi": {
                "Type": "AWS::AppSync::GraphQLApi",
                "Properties": {"Name": api_name, "AuthenticationType": "API_KEY"},
            },
            "ApiKey": {
                "Type": "AWS::AppSync::ApiKey",
                "Properties": {"ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]}},
            },
            "GraphQLSchema": {
                "Type": "AWS::AppSync::GraphQLSchema",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "Definition": schema,
                },
            },
            "OrdersDataSource": {
                "Type": "AWS::AppSync::DataSource",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "Name": orders_ds,
                    "Type": "AMAZON_DYNAMODB",
                    "DynamoDBConfig": {"TableName": orders_table, "AwsRegion": ctx.region},
                    "ServiceRoleArn": {"Fn::GetAtt": ["PipelineRole", "Arn"]},
                },
            },
            "AuditDataSource": {
                "Type": "AWS::AppSync::DataSource",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "Name": audit_ds,
                    "Type": "AMAZON_DYNAMODB",
                    "DynamoDBConfig": {"TableName": audit_table, "AwsRegion": ctx.region},
                    "ServiceRoleArn": {"Fn::GetAtt": ["PipelineRole", "Arn"]},
                },
            },
            "OrderFunction": {
                "Type": "AWS::AppSync::FunctionConfiguration",
                "DependsOn": "OrdersDataSource",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "Name": fn1_name,
                    "DataSourceName": orders_ds,
                    "FunctionVersion": "2018-05-29",
                    "RequestMappingTemplate": fn1_request_tpl,
                    "ResponseMappingTemplate": fn_response_tpl,
                },
            },
            "AuditFunction": {
                "Type": "AWS::AppSync::FunctionConfiguration",
                "DependsOn": "AuditDataSource",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "Name": fn2_name,
                    "DataSourceName": audit_ds,
                    "FunctionVersion": "2018-05-29",
                    "RequestMappingTemplate": fn2_request_tpl,
                    "ResponseMappingTemplate": fn_response_tpl,
                },
            },
            "PipelineResolver": {
                "Type": "AWS::AppSync::Resolver",
                "DependsOn": "GraphQLSchema",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "TypeName": "Mutation",
                    "FieldName": "createOrderWithAudit",
                    "Kind": "PIPELINE",
                    "PipelineConfig": {
                        "Functions": [
                            {"Fn::GetAtt": ["OrderFunction", "FunctionId"]},
                            {"Fn::GetAtt": ["AuditFunction", "FunctionId"]},
                        ]
                    },
                    "RequestMappingTemplate": pipeline_before_tpl,
                    "ResponseMappingTemplate": pipeline_after_tpl,
                },
            },
        },
        "Outputs": {
            "ApiUrl": {"Value": {"Fn::GetAtt": ["GraphQLApi", "GraphQLUrl"]}},
            "ApiKeyValue": {"Value": {"Fn::GetAtt": ["ApiKey", "ApiKey"]}},
        },
    }

    stack = _deploy_cfn(ctx, json.dumps(template))
    api_url = stack["outputs"]["ApiUrl"]
    api_key = stack["outputs"]["ApiKeyValue"]

    mutation = (
        "mutation Create($item: String!) "
        "{ createOrderWithAudit(item: $item) { orderId auditId } }"
    )
    item_value = "widget-42"
    status, payload = _graphql_request_stable(ctx, api_url, mutation, {"item": item_value}, api_key=api_key)
    assert status == 200, f"pipeline call failed: {status} {payload}"
    assert not payload.get("errors"), f"pipeline produced errors: {payload.get('errors')}"
    result = payload["data"]["createOrderWithAudit"]
    order_id = result["orderId"]
    audit_id = result["auditId"]
    assert order_id and audit_id and order_id != audit_id, (
        f"pipeline must stash two distinct autoId values: orderId={order_id!r} auditId={audit_id!r}"
    )

    ddb = ctx.client("dynamodb")
    order_item = ddb.get_item(TableName=orders_table, Key={"orderId": {"S": order_id}}).get("Item")
    assert order_item is not None, "order function did not write to the orders table"
    assert order_item["item"]["S"] == item_value, (
        f"expected orders.item={item_value!r}, got {order_item['item']['S']!r}"
    )

    audit_item = ddb.get_item(TableName=audit_table, Key={"auditId": {"S": audit_id}}).get("Item")
    assert audit_item is not None, "audit function did not write to the audit table"
    assert audit_item["orderId"]["S"] == order_id, "audit record must reference the SAME order id"
    assert audit_item["action"]["S"] == "CREATE", (
        f"expected audit.action='CREATE', got {audit_item['action']['S']!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _alnum_name(ctx: Any, kind: str) -> str:
    return _xname(ctx, kind).replace("-", "_")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _graphql_request(ctx, url, query, variables=None, api_key=None, id_token=None, timeout=30):
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(routed_url, data=body, method="POST", headers=route_headers)
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("x-api-key", api_key)
    if id_token:
        req.add_header("Authorization", id_token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        status = e.code
        payload = json.loads(e.read().decode())
    return status, payload


def _graphql_request_stable(ctx, url, query, variables=None, *, api_key=None, id_token=None, timeout_s=20.0, interval_s=2.0):
    """Like _graphql_request, but retries transient IAM-propagation AccessDenied errors from a
    just-created data source role -- a documented IAM eventual-consistency window, not a
    behavioral outcome under test. A deterministic 401 (wrong auth entirely) is NOT retried."""

    def _probe():
        return _graphql_request(ctx, url, query, variables, api_key=api_key, id_token=id_token)

    def _stable(result):
        status, payload = result
        if status != 200:
            return True
        errors = payload.get("errors") or []
        return not any("AccessDenied" in json.dumps(e) for e in errors)

    return _poll_until(_probe, _stable, timeout_s=timeout_s, interval_s=interval_s, description="GraphQL call past IAM propagation window")



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
