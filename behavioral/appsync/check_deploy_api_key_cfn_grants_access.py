"""deploy-api-key-cfn-grants-access."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deploy-api-key-cfn-grants-access"
GROUP = "deploy"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An AWS::AppSync::ApiKey deployed via CloudFormation authorizes a GraphQL request right after
    stack completion, and ListApiKeys reports its declared Description."""
    appsync = ctx.client("appsync")
    template = _template()
    outputs = _deploy_stack(ctx, template, {"ApiName": ctx.unique_name("sim2real-keyapi-")})

    api_id = outputs["ApiId"]
    graphql_url = outputs["GraphQLUrl"]
    api_key = outputs["ApiKeyValue"]

    api = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert api["authenticationType"] == "API_KEY", api["authenticationType"]

    keys = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    matching = [k for k in keys if k["id"] == api_key]
    assert len(matching) == 1, keys
    assert matching[0]["description"] == "sim2real-cfn-key", matching[0]["description"]

    # Immediately (no sleep, no retry) exercise the data plane with the CFN-issued key.
    probe_value = ctx.unique_name("key-grants-")
    status, body = _graphql_request(
        ctx, graphql_url, api_key, "query Echo($m: String) { echo(msg: $m) }", {"m": probe_value}
    )
    assert status == 200, body
    assert not body.get("errors"), body.get("errors")
    assert body["data"]["echo"] == probe_value, body["data"]


# ===== helpers =====


def _template() -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"ApiName": {"Type": "String"}},
        "Resources": {
            "GraphQLApi": {
                "Type": "AWS::AppSync::GraphQLApi",
                "Properties": {"Name": {"Ref": "ApiName"}, "AuthenticationType": "API_KEY"},
            },
            "ApiKey": {
                "Type": "AWS::AppSync::ApiKey",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "Description": "sim2real-cfn-key",
                },
            },
            "GraphQLSchema": {
                "Type": "AWS::AppSync::GraphQLSchema",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "Definition": (
                        "type Query {\n  echo(msg: String): String\n}\n"
                        "schema {\n  query: Query\n}\n"
                    ),
                },
            },
            "NoneDataSource": {
                "Type": "AWS::AppSync::DataSource",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "Name": "NoneDS",
                    "Type": "NONE",
                },
            },
            "EchoResolver": {
                "Type": "AWS::AppSync::Resolver",
                "DependsOn": ["GraphQLSchema", "NoneDataSource"],
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "TypeName": "Query",
                    "FieldName": "echo",
                    "DataSourceName": "NoneDS",
                    "Kind": "UNIT",
                    "Runtime": {"Name": "APPSYNC_JS", "RuntimeVersion": "1.0.0"},
                    "Code": (
                        "export function request(ctx) {\n  return {};\n}\n"
                        "export function response(ctx) {\n  return ctx.args.msg;\n}\n"
                    ),
                },
            },
        },
        "Outputs": {
            "ApiId": {"Value": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]}},
            "GraphQLUrl": {"Value": {"Fn::GetAtt": ["GraphQLApi", "GraphQLUrl"]}},
            "ApiKeyValue": {"Value": {"Fn::GetAtt": ["ApiKey", "ApiKey"]}},
        },
    }


def _deploy_stack(ctx, template: dict, parameters: dict, max_attempts: int = 90) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-appsync-stack-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts * 10 // 2}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts * 10 // 2}
    )
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _graphql_request(ctx, url: str, api_key: str, query: str, variables: dict | None = None):
    body = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "x-api-key": api_key, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
