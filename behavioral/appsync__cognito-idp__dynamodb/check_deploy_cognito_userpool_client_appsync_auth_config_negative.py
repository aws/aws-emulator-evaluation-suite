"""deploy-cognito-userpool-client-appsync-auth-config-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cognito-userpool-client-appsync-auth-config-negative"
GROUP = "overly-permissive"
SERVICES = ["appsync", "cognito-idp", "dynamodb"]


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With an additional Cognito auth provider wired to pool A, a valid token from pool B gets 401
    and writes nothing, while a token from pool A succeeds against the same API."""
    api_name = _xname(ctx, "api")
    pool_a_name = _xname(ctx, "pool-a")
    pool_b_name = _xname(ctx, "pool-b")
    client_a_name = _xname(ctx, "client-a")
    client_b_name = _xname(ctx, "client-b")
    role_name = _xname(ctx, "role")
    table_name = _xname(ctx, "tbl")
    ds_name = _alnum_name(ctx, "ds")

    schema = (
        "schema { query: Query mutation: Mutation }\n"
        "type Query { noop: String }\n"
        "type Mutation { createItem(id: ID!, value: String!): Item @aws_cognito_user_pools @aws_api_key }\n"
        "type Item @aws_cognito_user_pools @aws_api_key { id: ID! value: String }\n"
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

    password_policy = {
        "MinimumLength": 8,
        "RequireUppercase": True,
        "RequireLowercase": True,
        "RequireNumbers": True,
        "RequireSymbols": False,
    }

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
                                        "Action": ["dynamodb:PutItem"],
                                        "Resource": {"Fn::GetAtt": ["ItemsTable", "Arn"]},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            # PoolA is the one wired into the API's additional auth config.
            "PoolA": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {"UserPoolName": pool_a_name, "Policies": {"PasswordPolicy": password_policy}},
            },
            "PoolAClient": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "ClientName": client_a_name,
                    "UserPoolId": {"Ref": "PoolA"},
                    "GenerateSecret": False,
                    "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                },
            },
            # PoolB is a completely separate pool, never referenced by the API at all.
            "PoolB": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {"UserPoolName": pool_b_name, "Policies": {"PasswordPolicy": password_policy}},
            },
            "PoolBClient": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "ClientName": client_b_name,
                    "UserPoolId": {"Ref": "PoolB"},
                    "GenerateSecret": False,
                    "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                },
            },
            "GraphQLApi": {
                "Type": "AWS::AppSync::GraphQLApi",
                "Properties": {
                    "Name": api_name,
                    "AuthenticationType": "API_KEY",
                    "AdditionalAuthenticationProviders": [
                        {
                            "AuthenticationType": "AMAZON_COGNITO_USER_POOLS",
                            "UserPoolConfig": {"AwsRegion": ctx.region, "UserPoolId": {"Ref": "PoolA"}},
                        }
                    ],
                },
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
            "PoolAId": {"Value": {"Ref": "PoolA"}},
            "PoolAClientId": {"Value": {"Ref": "PoolAClient"}},
            "PoolBId": {"Value": {"Ref": "PoolB"}},
            "PoolBClientId": {"Value": {"Ref": "PoolBClient"}},
        },
    }

    stack = _deploy_cfn(ctx, json.dumps(template))
    api_url = stack["outputs"]["ApiUrl"]
    pool_a_id, client_a_id = stack["outputs"]["PoolAId"], stack["outputs"]["PoolAClientId"]
    pool_b_id, client_b_id = stack["outputs"]["PoolBId"], stack["outputs"]["PoolBClientId"]

    password = "TestPassw0rd"
    token_a = _create_cognito_user_and_get_id_token(
        ctx, pool_a_id, client_a_id, ctx.unique_name("sim2real-xsvc-usera-"), password
    )
    token_b = _create_cognito_user_and_get_id_token(
        ctx, pool_b_id, client_b_id, ctx.unique_name("sim2real-xsvc-userb-"), password
    )

    mutation = (
        "mutation Create($id: ID!, $value: String!) "
        "{ createItem(id: $id, value: $value) { id value } }"
    )
    ddb = ctx.client("dynamodb")

    # Negative: Pool B's token is rejected because the API's Cognito auth is wired to Pool A.
    id_b = ctx.unique_name("sim2real-xsvc-itemb-")
    status, payload = _graphql_request(ctx, api_url, mutation, {"id": id_b, "value": "x"}, id_token=token_b)
    assert status == 401, f"mismatched-pool token should be rejected with 401, got {status}: {payload}"
    assert payload.get("data") in (None, {}), "mismatched-pool call must not have mutated data"
    item = ddb.get_item(TableName=table_name, Key={"id": {"S": id_b}}).get("Item")
    assert item is None, "item must NOT be written when the presented token's pool doesn't match"

    # Positive control: Pool A's token IS the correctly-wired pool -> succeeds.
    id_a = ctx.unique_name("sim2real-xsvc-itema-")
    status, payload = _graphql_request_stable(ctx, api_url, mutation, {"id": id_a, "value": "ok"}, id_token=token_a)
    assert status == 200, f"correctly-wired pool token should succeed: {status} {payload}"
    assert not payload.get("errors"), f"correctly-wired pool token must not produce GraphQL errors: {payload}"
    assert payload["data"]["createItem"]["id"] == id_a, (
        f"expected createItem to echo id {id_a!r}, got {payload['data']}"
    )
    item = ddb.get_item(TableName=table_name, Key={"id": {"S": id_a}}).get("Item")
    assert item is not None and item["value"]["S"] == "ok", (
        f"expected item {id_a!r} with value 'ok' written by the correctly-wired pool call, got {item!r}"
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


def _graphql_request_stable(ctx, url, query, variables=None, *, api_key=None, id_token=None, timeout_s=90.0, interval_s=3.0):
    """Like _graphql_request, but retries transient IAM-propagation errors from a just-created
    data source role -- a documented IAM eventual-consistency window, not a behavioral outcome
    under test. A deterministic 401 (auth rejection) is NOT retried, as that is terminal;
    any GraphQL-level error on an otherwise-200 response is treated as the propagation window
    (AppSync/DynamoDB wrap the underlying denial under a few different error-type strings)."""

    def _probe():
        return _graphql_request(ctx, url, query, variables, api_key=api_key, id_token=id_token)

    def _stable(result):
        status, payload = result
        if status != 200:
            return True
        errors = payload.get("errors") or []
        return not errors

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
