"""deploy-api-key-cfn-grants-data-plane-access."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-api-key-cfn-grants-data-plane-access"
GROUP = "server-side"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An AWS::AppSync::ApiKey deployed via CloudFormation actually authorizes a live
    GraphQL request against the deployed API's HTTP endpoint, and a request missing
    the key is rejected -- not merely describable via GetGraphqlApi/ListApiKeys."""
    api_name = ctx.unique_name("sim2real-appsync-api-")
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
                    "Definition": "type Query {\n  ping: String\n}\n",
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
            "PingResolver": {
                "Type": "AWS::AppSync::Resolver",
                "DependsOn": ["Schema"],
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["Api", "ApiId"]},
                    "TypeName": "Query",
                    "FieldName": "ping",
                    "Kind": "UNIT",
                    "DataSourceName": {"Fn::GetAtt": ["NoneDS", "Name"]},
                    "RequestMappingTemplate": '{\n  "version": "2018-05-29",\n  "payload": {}\n}',
                    "ResponseMappingTemplate": '$util.toJson("pong")',
                },
            },
            "ApiKey": {
                "Type": "AWS::AppSync::ApiKey",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["Api", "ApiId"]},
                    "Description": "sim2real test key",
                },
            },
        },
        "Outputs": {
            "ApiId": {"Value": {"Fn::GetAtt": ["Api", "ApiId"]}},
            "ApiKeyValue": {"Value": {"Fn::GetAtt": ["ApiKey", "ApiKey"]}},
        },
    }

    stack_name, outputs = _deploy_stack(ctx, template, capabilities=[])
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    api_id = outputs["ApiId"]
    api_key = outputs["ApiKeyValue"]

    appsync = ctx.client("appsync")
    endpoint = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]["uris"]["GRAPHQL"]

    # Positive: the CFN-created key authorizes a real data-plane query.
    status, payload = _graphql_query(ctx, endpoint, api_key, "query { ping }")
    assert status == 200, f"authorized query got HTTP {status}: {payload}"
    assert "errors" not in payload, f"unexpected errors with valid key: {payload}"
    assert payload["data"]["ping"] == "pong", f"expected 'pong', got {payload['data']}"

    # Negative control (same file): a request with NO key is rejected, and no data
    # is returned for it -- the key is what is actually granting access, not an
    # emulator that lets every request through regardless of auth.
    status_noauth, payload_noauth = _graphql_query(ctx, endpoint, None, "query { ping }")
    assert status_noauth == 401, f"expected 401 without api key, got {status_noauth}: {payload_noauth}"
    assert payload_noauth.get("data") is None, f"expected no data without api key, got {payload_noauth.get('data')!r}"
    assert payload_noauth["errors"][0]["errorType"] == "UnauthorizedException", (
        f"expected errorType UnauthorizedException, got {payload_noauth.get('errors')}"
    )


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
    cfn.create_stack(**kwargs, Tags=[{"Key": "sim2real", "Value": CHECK}])
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


def _graphql_query(ctx, endpoint: str, api_key: str | None, query: str, variables: dict | None = None):
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["x-api-key"] = api_key
    body: dict[str, Any] = {"query": query}
    if variables:
        body["variables"] = variables
    return _http_post_json(ctx, endpoint, headers, body)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
