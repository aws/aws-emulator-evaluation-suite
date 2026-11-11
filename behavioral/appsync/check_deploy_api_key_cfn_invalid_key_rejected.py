"""deploy-api-key-cfn-invalid-key-rejected."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deploy-api-key-cfn-invalid-key-rejected"
GROUP = "deploy"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A tampered x-api-key on a CFN-deployed API_KEY GraphQL API gets HTTP 401
    UnauthorizedException and no data, while the genuine key authorizes requests before and after.
    """
    template = _template()
    outputs = _deploy_stack(ctx, template, {"ApiName": ctx.unique_name("sim2real-badkeyapi-")})

    graphql_url = outputs["GraphQLUrl"]
    api_key = outputs["ApiKeyValue"]
    query = "query Echo($m: String) { echo(msg: $m) }"

    probe1 = ctx.unique_name("good-key-")
    status, body = _graphql_request(ctx, graphql_url, api_key, query, {"m": probe1})
    assert status == 200, f"expected HTTP 200 for genuine key, got {status}: {body}"
    assert body["data"]["echo"] == probe1, f"expected echo={probe1!r}, got {body}"

    bad_key = api_key[:-1] + ("0" if api_key[-1] != "0" else "1")
    assert bad_key != api_key, "tampered key must differ from the genuine key"

    status2, body2 = _graphql_request(ctx, graphql_url, bad_key, query, {"m": probe1})
    assert status2 == 401, f"expected HTTP 401 for tampered key, got {status2}: {body2}"
    assert not body2.get("data"), f"unauthorized request must not return data: {body2}"
    errors2 = body2.get("errors") or []
    assert errors2, f"expected a GraphQL error envelope for tampered key, got {body2}"
    assert errors2[0].get("errorType") == "UnauthorizedException", errors2[0]

    probe2 = ctx.unique_name("good-key-again-")
    status3, body3 = _graphql_request(ctx, graphql_url, api_key, query, {"m": probe2})
    assert status3 == 200, f"expected HTTP 200 for genuine key (post-rejection), got {status3}: {body3}"
    assert body3["data"]["echo"] == probe2, f"expected echo={probe2!r}, got {body3}"




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
                "Properties": {"ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]}},
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
