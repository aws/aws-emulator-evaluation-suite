"""deploy-resolver-cfn-pipeline-executes."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deploy-resolver-cfn-pipeline-executes"
GROUP = "deploy"
SERVICES = ["appsync"]

_SIM2REAL_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-appsync-stack"},
]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A PIPELINE resolver and its two functions deployed via CloudFormation run the full chain at
    query time: stash values set in function 1 reach function 2 and the resolver's response."""
    appsync = ctx.client("appsync")
    template = _pipeline_template()
    outputs = _deploy_stack(ctx, template, {"ApiName": ctx.unique_name("sim2real-pipeapi-")})

    api_id = outputs["ApiId"]
    graphql_url = outputs["GraphQLUrl"]
    api_key = outputs["ApiKeyValue"]
    func1_id = outputs["Func1Id"]
    func2_id = outputs["Func2Id"]

    # Control-plane: the resolver is really PIPELINE and chains both functions, and each
    # function's JS code matches what was declared in the template.
    resolver = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="pipelineTest")["resolver"]
    assert resolver["kind"] == "PIPELINE", f"expected kind=PIPELINE, got {resolver['kind']!r}"
    assert resolver["pipelineConfig"]["functions"] == [func1_id, func2_id], (
        f"expected pipeline functions [{func1_id}, {func2_id}], "
        f"got {resolver['pipelineConfig']['functions']!r}"
    )

    func1 = appsync.get_function(apiId=api_id, functionId=func1_id)["functionConfiguration"]
    assert "stash.step1" in func1["code"], f"expected 'stash.step1' in Func1 code, got: {func1['code']!r}"
    func2 = appsync.get_function(apiId=api_id, functionId=func2_id)["functionConfiguration"]
    assert "stash.step2" in func2["code"], f"expected 'stash.step2' in Func2 code, got: {func2['code']!r}"

    # Data-plane: drive a real query and confirm the stash value written by Function 1
    # was actually visible to and combined by Function 2, then surfaced by the resolver.
    status, body = _graphql_request(ctx, graphql_url, api_key, "query { pipelineTest }")
    assert status == 200, f"expected HTTP 200, got {status}: {body}"
    assert not body.get("errors"), f"expected no GraphQL errors, got {body.get('errors')}"
    assert body["data"]["pipelineTest"] == "step1-step2", (
        f"expected pipelineTest == 'step1-step2', got {body['data']['pipelineTest']!r}"
    )


# ===== helpers =====

_JS_RUNTIME = {"Name": "APPSYNC_JS", "RuntimeVersion": "1.0.0"}


def _pipeline_template() -> dict:
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
                        "type Query {\n  pipelineTest: String\n}\n"
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
            "Func1": {
                "Type": "AWS::AppSync::FunctionConfiguration",
                "DependsOn": ["NoneDataSource"],
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "Name": "Func1",
                    "DataSourceName": "NoneDS",
                    "Runtime": _JS_RUNTIME,
                    "Code": (
                        "export function request(ctx) {\n"
                        "  ctx.stash.step1 = \"step1\";\n"
                        "  return {};\n"
                        "}\n"
                        "export function response(ctx) {\n"
                        "  return ctx.stash.step1;\n"
                        "}\n"
                    ),
                },
            },
            "Func2": {
                "Type": "AWS::AppSync::FunctionConfiguration",
                "DependsOn": ["NoneDataSource"],
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "Name": "Func2",
                    "DataSourceName": "NoneDS",
                    "Runtime": _JS_RUNTIME,
                    "Code": (
                        "export function request(ctx) {\n"
                        "  ctx.stash.step2 = ctx.stash.step1 + \"-step2\";\n"
                        "  return {};\n"
                        "}\n"
                        "export function response(ctx) {\n"
                        "  return ctx.stash.step2;\n"
                        "}\n"
                    ),
                },
            },
            "PipelineResolver": {
                "Type": "AWS::AppSync::Resolver",
                "DependsOn": ["GraphQLSchema", "Func1", "Func2"],
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "TypeName": "Query",
                    "FieldName": "pipelineTest",
                    "Kind": "PIPELINE",
                    "PipelineConfig": {
                        "Functions": [
                            {"Fn::GetAtt": ["Func1", "FunctionId"]},
                            {"Fn::GetAtt": ["Func2", "FunctionId"]},
                        ]
                    },
                    "Runtime": _JS_RUNTIME,
                    "Code": (
                        "export function request(ctx) {\n  return {};\n}\n"
                        "export function response(ctx) {\n  return ctx.prev.result;\n}\n"
                    ),
                },
            },
        },
        "Outputs": {
            "ApiId": {"Value": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]}},
            "GraphQLUrl": {"Value": {"Fn::GetAtt": ["GraphQLApi", "GraphQLUrl"]}},
            "ApiKeyValue": {"Value": {"Fn::GetAtt": ["ApiKey", "ApiKey"]}},
            "Func1Id": {"Value": {"Fn::GetAtt": ["Func1", "FunctionId"]}},
            "Func2Id": {"Value": {"Fn::GetAtt": ["Func2", "FunctionId"]}},
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
        Tags=_SIM2REAL_TAGS,
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
