"""deploy-pipeline-function-cfn-js-runtime-code-update-in-place."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-pipeline-function-cfn-js-runtime-code-update-in-place"
GROUP = "deploy"
SERVICES = ["appsync", "cloudformation"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


def _poll_stack(cfn, stack_id, timeout_s=300.0):
    """Poll ``DescribeStacks`` until the stack's status settles; return that status."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} stuck at {status!r} after {timeout_s:.0f}s")
        time.sleep(3)


def _fail_reasons(cfn, stack_id):
    """``{logical id: reason}`` of every non-progress event, for a readable deploy failure."""
    events = cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
    return {
        e["LogicalResourceId"]: e.get("ResourceStatusReason")
        for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
    }


def _delete_stack(cfn, stack_id, timeout_s=300.0):
    """Delete the stack by id and wait for ``DELETE_COMPLETE``; a ``DELETE_FAILED`` raises."""
    cfn.delete_stack(StackName=stack_id)
    status = _poll_stack(cfn, stack_id, timeout_s)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {_fail_reasons(cfn, stack_id)}")


def _not_found(fn):
    """``(code, message)`` of the ``ClientError`` ``fn()`` raises; a success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected NotFoundException, call succeeded with {result!r}")


def _poll_graphql_query(ctx, endpoint, api_key, query, field, want, timeout_s=60.0):
    """Poll the query until ``field`` reads ``want``; a resolver update can lag a moment."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, payload = _graphql_query(ctx, endpoint, api_key, query)
        assert status == 200 and "errors" not in payload, payload
        if payload["data"][field] == want:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"query still answers {payload['data'][field]!r}, not {want!r}")
        time.sleep(2)


def _graphql_query(ctx, endpoint, api_key, query):
    url, route_headers = ctx.endpoint_route(endpoint)
    headers = {"content-type": "application/json", "x-api-key": api_key, **route_headers}
    req = urllib.request.Request(url, data=json.dumps({"query": query}).encode(),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20.0) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


# JS pipeline function code. v1 and v2 differ only in the suffix they append, so a query made
# after the update proves the deployed Code actually changed, not just its stored text.
_CODE_V1 = (
    "export function request(ctx) {\n  return {};\n}\n"
    "export function response(ctx) {\n  return `${ctx.args.msg}-js-v1`;\n}\n"
)
_CODE_V2 = (
    "export function request(ctx) {\n  return {};\n}\n"
    "export function response(ctx) {\n  return `${ctx.args.msg}-js-v2`;\n}\n"
)
_API_GONE = ("NotFoundException", "API not found.")


def _template(api_name, code):
    return json.dumps({
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
                    "Definition": "type Query {\n  batchEcho(msg: String): String\n}\n",
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
                    "Name": "BatchEchoFn",
                    "DataSourceName": {"Fn::GetAtt": ["NoneDS", "Name"]},
                    "Runtime": {"Name": "APPSYNC_JS", "RuntimeVersion": "1.0.0"},
                    "Code": code,
                },
            },
            "PipelineResolver": {
                "Type": "AWS::AppSync::Resolver",
                "DependsOn": ["Schema", "Func"],
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["Api", "ApiId"]},
                    "TypeName": "Query",
                    "FieldName": "batchEcho",
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
            "FunctionArn": {"Value": {"Fn::GetAtt": ["Func", "FunctionArn"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:data-plane",
      "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN FunctionConfiguration's APPSYNC_JS Runtime and Code drive its pipeline stage.

    Code updates in place under the same FunctionId, and a query made right after reflects the
    newly deployed Code; deleting the stack leaves neither the function nor the API behind.
    """
    cfn = ctx.client("cloudformation")
    appsync = ctx.client("appsync")
    api_name = ctx.unique_name("sim2real-appsync-jsfn-api-")

    stack_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-appsync-jsfn-"),
        TemplateBody=_template(api_name, _CODE_V1),
        Capabilities=["CAPABILITY_IAM"],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _poll_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"create ended {status!r}: {_fail_reasons(cfn, stack_id)}"
    out = {o["OutputKey"]: o["OutputValue"]
           for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    api_id, function_id, function_arn = out["ApiId"], out["FunctionId"], out["FunctionArn"]

    func = appsync.get_function(apiId=api_id, functionId=function_id)["functionConfiguration"]
    assert func["code"] == _CODE_V1, func["code"]
    assert (func["runtime"]["name"], func["runtime"]["runtimeVersion"]) == ("APPSYNC_JS", "1.0.0"), func
    assert func["functionArn"] == function_arn, (func["functionArn"], function_arn)

    api_key = appsync.create_api_key(apiId=api_id, description="sim2real-jsfn-key")["apiKey"]["id"]
    endpoint = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]["uris"]["GRAPHQL"]
    status, payload = _graphql_query(ctx, endpoint, api_key, 'query { batchEcho(msg: "hi") }')
    assert status == 200 and "errors" not in payload, payload
    assert payload["data"]["batchEcho"] == "hi-js-v1", payload

    # In-place update: only Code changes; ApiId does not, so FunctionId stays the same.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(api_name, _CODE_V2))
    status = _poll_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"update ended {status!r}: {_fail_reasons(cfn, stack_id)}"
    out2 = {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    assert (out2["FunctionId"], out2["FunctionArn"]) == (function_id, function_arn), (
        "an in-place update must keep the same FunctionConfiguration identity", out2
    )

    func = appsync.get_function(apiId=api_id, functionId=function_id)["functionConfiguration"]
    assert func["code"] == _CODE_V2, func["code"]

    _poll_graphql_query(ctx, endpoint, api_key, 'query { batchEcho(msg: "hi") }', "batchEcho", "hi-js-v2")

    _delete_stack(cfn, stack_id)
    got = _not_found(lambda: appsync.get_function(apiId=api_id, functionId=function_id))
    assert got == _API_GONE, got
    got = _not_found(lambda: appsync.get_graphql_api(apiId=api_id))
    assert got == _API_GONE, got


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
