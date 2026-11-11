"""deploy-appsync-ddb-missing-datasource-role-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-appsync-ddb-missing-datasource-role-negative"
GROUP = "overly-permissive"
SERVICES = ["appsync", "cognito-idp", "dynamodb"]


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A stack whose DynamoDB data source role omits dynamodb:PutItem deploys, but its resolver
    returns a GraphQL error and writes nothing, while a sibling resolver whose role has the
    permission writes to the same table."""
    table_name = _xname(ctx, "tbl")
    good_role_name = _xname(ctx, "good-role")
    bad_role_name = _xname(ctx, "bad-role")
    api_name = _xname(ctx, "api")
    good_ds_name = _alnum_name(ctx, "gds")
    bad_ds_name = _alnum_name(ctx, "bds")

    schema = (
        "schema { query: Query mutation: Mutation }\n"
        "type Query { noop: String }\n"
        "type Mutation {\n"
        "  createItemGood(id: ID!, value: String!): Item\n"
        "  createItemBad(id: ID!, value: String!): Item\n"
        "}\n"
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
    response_tpl = (
        "#if($ctx.error)\n"
        "  $util.error($ctx.error.message, $ctx.error.type)\n"
        "#end\n"
        "$util.toJson($ctx.result)"
    )

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
            "GoodRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": good_role_name,
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
                            "PolicyName": "ddb-write",
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
            "BadRole": {
                # Trust policy only -- AppSync CAN assume this role, but it grants NO
                # DynamoDB permissions at all, so the resolver's PutItem call is denied.
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": bad_role_name,
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
            "GoodDataSource": {
                "Type": "AWS::AppSync::DataSource",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "Name": good_ds_name,
                    "Type": "AMAZON_DYNAMODB",
                    "DynamoDBConfig": {"TableName": table_name, "AwsRegion": ctx.region},
                    "ServiceRoleArn": {"Fn::GetAtt": ["GoodRole", "Arn"]},
                },
            },
            "BadDataSource": {
                "Type": "AWS::AppSync::DataSource",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "Name": bad_ds_name,
                    "Type": "AMAZON_DYNAMODB",
                    "DynamoDBConfig": {"TableName": table_name, "AwsRegion": ctx.region},
                    "ServiceRoleArn": {"Fn::GetAtt": ["BadRole", "Arn"]},
                },
            },
            "GoodResolver": {
                "Type": "AWS::AppSync::Resolver",
                "DependsOn": ["GraphQLSchema", "GoodDataSource"],
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "TypeName": "Mutation",
                    "FieldName": "createItemGood",
                    "DataSourceName": good_ds_name,
                    "RequestMappingTemplate": request_tpl,
                    "ResponseMappingTemplate": response_tpl,
                },
            },
            "BadResolver": {
                "Type": "AWS::AppSync::Resolver",
                "DependsOn": ["GraphQLSchema", "BadDataSource"],
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "TypeName": "Mutation",
                    "FieldName": "createItemBad",
                    "DataSourceName": bad_ds_name,
                    "RequestMappingTemplate": request_tpl,
                    "ResponseMappingTemplate": response_tpl,
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
    ddb = ctx.client("dynamodb")

    # Negative: the data source role has no write permission -> resolver call fails, no item.
    # The role was just created; AppSync may transiently fail to assume it until the
    # trust/policy change propagates ("Unable to assume role..."). Poll past that noise and
    # only stop once we see a definitive (non-role-assumption) rejection.
    bad_id = ctx.unique_name("sim2real-xsvc-baditem-")
    mutation_bad = (
        "mutation Create($id: ID!, $value: String!) "
        "{ createItemBad(id: $id, value: $value) { id value } }"
    )

    def _is_definitive_bad_response(result: tuple[int, dict[str, Any]]) -> bool:
        resp_status, resp_payload = result
        if resp_status != 200:
            return True
        errors = resp_payload.get("errors") or []
        if not errors:
            return False
        combined = " ".join(json.dumps(e) for e in errors).lower()
        return "unable to assume role" not in combined

    status, payload = _poll_until(
        lambda: _graphql_request(
            ctx, api_url, mutation_bad, {"id": bad_id, "value": "should-not-persist"}, api_key=api_key
        ),
        _is_definitive_bad_response,
        timeout_s=30.0,
        interval_s=3.0,
        description="GraphQL call past IAM propagation window (negative)",
    )
    assert status == 200, f"expected HTTP 200 with a GraphQL-level error, got {status}: {payload}"
    errors = payload.get("errors") or []
    assert errors, f"expected a GraphQL error for the unauthorized role: {payload}"
    first_error = errors[0] if isinstance(errors[0], dict) else {}
    error_type = str(first_error.get("errorType", ""))
    error_message = str(first_error.get("message", ""))
    assert (
        "accessdenied" in error_type.lower()
        or "accessdenied" in error_message.lower()
        or "not authorized" in error_message.lower()
    ), f"expected an access-denied rejection, got: {first_error}"
    assert payload["data"] is None or payload["data"].get("createItemBad") is None, (
        f"expected createItemBad to be null on rejection, got data={payload.get('data')!r}"
    )
    item = ddb.get_item(TableName=table_name, Key={"id": {"S": bad_id}}).get("Item")
    assert item is None, f"item must NOT be written when the data source role lacks permission, got {item!r}"

    # Positive control: same table, same call shape, role WITH the permission -> succeeds.
    good_id = ctx.unique_name("sim2real-xsvc-gooditem-")
    mutation_good = (
        "mutation Create($id: ID!, $value: String!) "
        "{ createItemGood(id: $id, value: $value) { id value } }"
    )
    status, payload = _graphql_request_stable(
        ctx, api_url, mutation_good, {"id": good_id, "value": "persists"}, api_key=api_key
    )
    assert status == 200, f"positive control failed: {status} {payload}"
    assert not payload.get("errors"), f"positive control produced errors: {payload.get('errors')}"
    assert payload["data"]["createItemGood"]["id"] == good_id, (
        f"expected createItemGood.id == {good_id!r}, got {payload['data']!r}"
    )
    item = ddb.get_item(TableName=table_name, Key={"id": {"S": good_id}}).get("Item")
    assert item is not None, "positive control item should have been written"
    assert item["value"]["S"] == "persists", f"expected value 'persists', got {item['value']!r}"


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
