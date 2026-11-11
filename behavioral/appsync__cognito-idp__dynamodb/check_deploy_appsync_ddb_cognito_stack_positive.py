"""deploy-appsync-ddb-cognito-stack-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-appsync-ddb-cognito-stack-positive"
GROUP = "deployment-order"
SERVICES = ["appsync", "cognito-idp", "dynamodb"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN stack wiring AppSync + a DynamoDB data source + Cognito User Pool auth lets an
    authenticated mutation persist data, while an unauthenticated call is rejected outright."""
    table_name = _xname(ctx, "tbl")
    role_name = _xname(ctx, "role")
    pool_name = _xname(ctx, "pool")
    client_name = _xname(ctx, "client")
    api_name = _xname(ctx, "api")
    ds_name = _alnum_name(ctx, "ds")

    schema = (
        "schema { query: Query mutation: Mutation }\n"
        "type Query { getItem(id: ID!): Item }\n"
        "type Mutation { createItem(id: ID!, value: String!): Item }\n"
        "type Item { id: ID! value: String }\n"
    )
    request_tpl = (
        "{\n"
        '  "version": "2018-05-29",\n'
        '  "operation": "PutItem",\n'
        '  "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.args.id) },\n'
        '  "attributeValues": { "value": $util.dynamodb.toDynamoDBJson($ctx.args.value) }\n'
        "}"
    )
    response_tpl = "$util.toJson($ctx.result)"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ItemsTable": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": table_name,
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
                },
            },
            "DynamoRole": {
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
                                        "Resource": {"Fn::GetAtt": ["ItemsTable", "Arn"]},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "UserPool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {
                    "UserPoolName": pool_name,
                    "Policies": {
                        "PasswordPolicy": {
                            "MinimumLength": 8,
                            "RequireUppercase": True,
                            "RequireLowercase": True,
                            "RequireNumbers": True,
                            "RequireSymbols": False,
                        }
                    },
                },
            },
            "UserPoolClient": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "ClientName": client_name,
                    "UserPoolId": {"Ref": "UserPool"},
                    "GenerateSecret": False,
                    "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                },
            },
            "GraphQLApi": {
                "Type": "AWS::AppSync::GraphQLApi",
                "Properties": {
                    "Name": api_name,
                    "AuthenticationType": "AMAZON_COGNITO_USER_POOLS",
                    "UserPoolConfig": {
                        "AwsRegion": ctx.region,
                        "DefaultAction": "ALLOW",
                        "UserPoolId": {"Ref": "UserPool"},
                    },
                },
            },
            "GraphQLSchema": {
                "Type": "AWS::AppSync::GraphQLSchema",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "Definition": schema,
                },
            },
            "ItemsDataSource": {
                "Type": "AWS::AppSync::DataSource",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "Name": ds_name,
                    "Type": "AMAZON_DYNAMODB",
                    "DynamoDBConfig": {"TableName": table_name, "AwsRegion": ctx.region},
                    "ServiceRoleArn": {"Fn::GetAtt": ["DynamoRole", "Arn"]},
                },
            },
            "CreateItemResolver": {
                "Type": "AWS::AppSync::Resolver",
                "DependsOn": ["GraphQLSchema", "ItemsDataSource"],
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "TypeName": "Mutation",
                    "FieldName": "createItem",
                    "DataSourceName": ds_name,
                    "RequestMappingTemplate": request_tpl,
                    "ResponseMappingTemplate": response_tpl,
                },
            },
        },
        "Outputs": {
            "ApiUrl": {"Value": {"Fn::GetAtt": ["GraphQLApi", "GraphQLUrl"]}},
            "UserPoolId": {"Value": {"Ref": "UserPool"}},
            "UserPoolClientId": {"Value": {"Ref": "UserPoolClient"}},
        },
    }

    stack = _deploy_cfn(ctx, json.dumps(template))
    api_url = stack["outputs"]["ApiUrl"]
    user_pool_id = stack["outputs"]["UserPoolId"]
    client_id = stack["outputs"]["UserPoolClientId"]

    username = ctx.unique_name("sim2real-xsvc-user-")
    password = "TestPassw0rd"
    id_token = _create_cognito_user_and_get_id_token(ctx, user_pool_id, client_id, username, password)

    item_id = ctx.unique_name("sim2real-xsvc-item-")
    mutation = "mutation Create($id: ID!, $value: String!) { createItem(id: $id, value: $value) { id value } }"

    ddb = ctx.client("dynamodb")

    # 1. Unauthenticated call (no token at all) must be rejected by Cognito auth enforcement.
    status, payload = _graphql_request(ctx, api_url, mutation, {"id": item_id, "value": "nope"})
    assert status == 401, f"expected 401 for missing auth, got {status}: {payload}"
    assert payload.get("data") in (None, {}), f"unauthenticated call should not mutate data: {payload}"
    unauth_item = ddb.get_item(TableName=table_name, Key={"id": {"S": item_id}}).get("Item")
    assert unauth_item is None, (
        f"unauthenticated mutation must not reach DynamoDB, but found item: {unauth_item}"
    )

    # 2. Authenticated mutation persists the item.
    status, payload = _graphql_request_stable(
        ctx, api_url, mutation, {"id": item_id, "value": "hello"}, id_token=id_token
    )
    assert status == 200, f"authenticated call failed: {status} {payload}"
    assert not payload.get("errors"), f"unexpected GraphQL errors: {payload.get('errors')}"
    assert payload["data"]["createItem"]["id"] == item_id, (
        f"expected createItem.id {item_id!r}, got {payload['data']['createItem'].get('id')!r}"
    )
    assert payload["data"]["createItem"]["value"] == "hello", (
        f"expected createItem.value 'hello', got {payload['data']['createItem'].get('value')!r}"
    )

    item = ddb.get_item(TableName=table_name, Key={"id": {"S": item_id}}).get("Item")
    assert item is not None, "item was not persisted to DynamoDB"
    assert item["value"]["S"] == "hello", f"expected DynamoDB value 'hello', got {item['value']}"


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
    """AppSync DataSource/Function names must match [_A-Za-z][_0-9A-Za-z]* (no hyphens)."""
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



def _create_cognito_user_and_get_id_token(ctx, user_pool_id, client_id, username, password):
    cognito = ctx.client("cognito-idp")
    cognito.admin_create_user(
        UserPoolId=user_pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(
        UserPoolId=user_pool_id, Username=username, Password=password, Permanent=True
    )
    resp = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]["IdToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
