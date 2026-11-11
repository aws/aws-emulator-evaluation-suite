"""deploy-function-cfn-pipeline-resolver-invocable."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-function-cfn-pipeline-resolver-invocable"
GROUP = "server-side"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::AppSync::FunctionConfiguration in a PIPELINE resolver runs as
    a pipeline stage: its request-mapping transformation shows in the final query result."""
    api_name = ctx.unique_name("sim2real-appsync-api-")
    func_request = (
        '#set($output = "${context.arguments.msg}-processed")\n'
        '{\n'
        '  "version": "2018-05-29",\n'
        '  "payload": "$output"\n'
        '}'
    )
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Api": {
                "Type": "AWS::AppSync::GraphQLApi",
                "Properties": {"Name": api_name, "AuthenticationType": "API_KEY"},
            },
            "Schema": {
                "Type": "AWS::AppSync::GraphQLSchema",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["Api", "ApiId"]},
                    "Definition": "type Query {\n  pipelineEcho(msg: String): String\n}\n",
                },
            },
            "NoneDS": {
                "Type": "AWS::AppSync::DataSource",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["Api", "ApiId"]},
                    "Name": "NoneDS",
                    "Type": "NONE",
                },
            },
            "Func": {
                "Type": "AWS::AppSync::FunctionConfiguration",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["Api", "ApiId"]},
                    "Name": "AppendProcessed",
                    "DataSourceName": {"Fn::GetAtt": ["NoneDS", "Name"]},
                    "FunctionVersion": "2018-05-29",
                    "RequestMappingTemplate": func_request,
                    "ResponseMappingTemplate": "$util.toJson($context.result)",
                },
            },
            "PipelineResolver": {
                "Type": "AWS::AppSync::Resolver",
                "DependsOn": ["Schema", "Func"],
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["Api", "ApiId"]},
                    "TypeName": "Query",
                    "FieldName": "pipelineEcho",
                    "Kind": "PIPELINE",
                    "PipelineConfig": {"Functions": [{"Fn::GetAtt": ["Func", "FunctionId"]}]},
                    "RequestMappingTemplate": "{}",
                    "ResponseMappingTemplate": "$util.toJson($ctx.prev.result)",
                },
            },
        },
        "Outputs": {
            "ApiId": {"Value": {"Fn::GetAtt": ["Api", "ApiId"]}},
            "FunctionId": {"Value": {"Fn::GetAtt": ["Func", "FunctionId"]}},
        },
    }

    stack_name, outputs = _deploy_stack(ctx, template, capabilities=[])
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    api_id = outputs["ApiId"]
    function_id = outputs["FunctionId"]

    appsync = ctx.client("appsync")
    func = appsync.get_function(apiId=api_id, functionId=function_id)["functionConfiguration"]
    assert func["dataSourceName"] == "NoneDS", (
        f"expected function data source 'NoneDS', got {func['dataSourceName']!r}"
    )

    resolver = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="pipelineEcho")["resolver"]
    assert resolver["kind"] == "PIPELINE", f"expected resolver kind 'PIPELINE', got {resolver['kind']!r}"
    assert resolver["pipelineConfig"]["functions"] == [function_id], (
        f"expected pipeline functions [{function_id!r}], got {resolver['pipelineConfig']['functions']!r}"
    )

    api_key = appsync.create_api_key(apiId=api_id, description="sim2real test key")["apiKey"]["id"]
    endpoint = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]["uris"]["GRAPHQL"]

    status, payload = _graphql_query(
        ctx, endpoint, api_key, 'query { pipelineEcho(msg: "hi") }'
    )
    assert status == 200 and "errors" not in payload, f"pipeline query failed: {payload}"
    assert payload["data"]["pipelineEcho"] == "hi-processed", (
        "the pipeline function's transformation did not reach the resolver's final "
        f"result: {payload}"
    )


# ===== helpers =====


def _deploy_stack(ctx: Any, template: dict, capabilities=None, params=None):
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-appsync-cfn-")
    kwargs = {
        "StackName": name,
        "TemplateBody": json.dumps(template),
        "Capabilities": capabilities if capabilities is not None else ["CAPABILITY_IAM"],
    }
    if params:
        kwargs["Parameters"] = params
    cfn.create_stack(**kwargs)
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})
    outputs_raw = cfn.describe_stacks(StackName=name)["Stacks"][0].get("Outputs", [])
    outputs = {o["OutputKey"]: o["OutputValue"] for o in outputs_raw}
    return name, outputs


def _delete_stack(ctx: Any, name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})


def _http_post_json(ctx, url: str, headers: dict, body_obj: dict, timeout: float = 20.0):
    data = json.dumps(body_obj).encode("utf-8")
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(routed_url, data=data, headers={**headers, **route_headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _graphql_query(ctx, endpoint: str, api_key: str, query: str, variables: dict | None = None):
    headers = {"Content-Type": "application/json", "x-api-key": api_key}
    body: dict[str, Any] = {"query": query}
    if variables:
        body["variables"] = variables
    return _http_post_json(ctx, endpoint, headers, body)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
