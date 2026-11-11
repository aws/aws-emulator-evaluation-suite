"""deploy-graphql-api-cfn-behaves-live-query."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deploy-graphql-api-cfn-behaves-live-query"
GROUP = "deploy"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A GraphQL API + schema + NONE data source + JS resolver deployed entirely via
    AWS::AppSync::GraphQLApi CFN resources resolves a live query correctly -- not merely
    reaching CREATE_COMPLETE."""
    appsync = ctx.client("appsync")
    template = _echo_template()
    outputs = _deploy_stack(ctx, template, {"ApiName": ctx.unique_name("sim2real-echoapi-")})

    api_id = outputs["ApiId"]
    graphql_url = outputs["GraphQLUrl"]
    api_key = outputs["ApiKeyValue"]

    # Control-plane state matches what CFN declared.
    api = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert api["authenticationType"] == "API_KEY", f"expected API_KEY auth, got {api['authenticationType']!r}"

    resolver = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="echo")["resolver"]
    assert resolver["kind"] == "UNIT", f"expected UNIT resolver, got {resolver['kind']!r}"
    assert resolver["dataSourceName"] == "NoneDS", (
        f"expected resolver wired to NoneDS, got {resolver['dataSourceName']!r}"
    )

    schema_text = appsync.get_introspection_schema(apiId=api_id, format="SDL")["schema"].read().decode("utf-8")
    assert "echo" in schema_text, f"expected 'echo' field in introspected schema, got: {schema_text!r}"

    # Now drive a REAL data-plane query against the deployed endpoint and assert the
    # resolver's JS code actually ran (echoes the argument back).
    probe_value = ctx.unique_name("echo-value-")
    status, body = _graphql_request(
        ctx, graphql_url, api_key, "query Echo($m: String) { echo(msg: $m) }", {"m": probe_value}
    )
    assert status == 200, f"expected HTTP 200 from the deployed GraphQL endpoint, got {status}: {body}"
    assert not body.get("errors"), f"expected no GraphQL errors, got {body.get('errors')}"
    assert body["data"]["echo"] == probe_value, (
        f"expected JS resolver to echo {probe_value!r} back, got {body['data'].get('echo')!r}"
    )


def _echo_template() -> dict:
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
