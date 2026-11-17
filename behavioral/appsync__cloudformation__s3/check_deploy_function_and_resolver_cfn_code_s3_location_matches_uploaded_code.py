"""deploy-function-and-resolver-cfn-code-s3-location-matches-uploaded-code."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-function-and-resolver-cfn-code-s3-location-matches-uploaded-code"
GROUP = "deploy"
SERVICES = ["appsync", "cloudformation", "s3"]

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
    }
)
_RUNTIME = {"Name": "APPSYNC_JS", "RuntimeVersion": "1.0.0"}
_FUNC_JS = (
    "export function request(ctx) { return {}; }\n"
    "export function response(ctx) { return 's3-function-result'; }\n"
)
_RESOLVER_JS = (
    "export function request(ctx) { return {}; }\n"
    "export function response(ctx) { return ctx.prev.result; }\n"
)


def _template() -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"ApiName": {"Type": "String"}, "CodeBucket": {"Type": "String"}},
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
                        "type Query {\n  s3CodeTest: String\n}\nschema {\n  query: Query\n}\n"
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
                    "Runtime": _RUNTIME,
                    "CodeS3Location": {"Fn::Sub": "s3://${CodeBucket}/func.js"},
                },
            },
            "PipelineResolver": {
                "Type": "AWS::AppSync::Resolver",
                "DependsOn": ["GraphQLSchema", "Func1"],
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                    "TypeName": "Query",
                    "FieldName": "s3CodeTest",
                    "Kind": "PIPELINE",
                    "PipelineConfig": {"Functions": [{"Fn::GetAtt": ["Func1", "FunctionId"]}]},
                    "Runtime": _RUNTIME,
                    "CodeS3Location": {"Fn::Sub": "s3://${CodeBucket}/resolver.js"},
                },
            },
        },
        "Outputs": {
            "ApiId": {"Value": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]}},
            "GraphQLUrl": {"Value": {"Fn::GetAtt": ["GraphQLApi", "GraphQLUrl"]}},
            "ApiKeyValue": {"Value": {"Fn::GetAtt": ["ApiKey", "ApiKey"]}},
            "FunctionId": {"Value": {"Fn::GetAtt": ["Func1", "FunctionId"]}},
            "FunctionArn": {"Value": {"Fn::GetAtt": ["Func1", "FunctionArn"]}},
            "ResolverArn": {"Value": {"Fn::GetAtt": ["PipelineResolver", "ResolverArn"]}},
        },
    }


def _wait_stack(cf, stack_id: str, terminal=_TERMINAL, timeout_s: float = 600.0) -> str:
    """Poll by StackId: once DELETE_COMPLETE, DescribeStacks(StackName=<name>) can 404."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _delete_stack(cf, stack_id: str) -> None:
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    status = _wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert status == "DELETE_COMPLETE", f"stack {stack_id} delete ended {status!r}"


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _graphql_request(ctx, url: str, api_key: str, query: str):
    body = json.dumps({"query": query, "variables": {}}).encode("utf-8")
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


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A FunctionConfiguration and a pipeline Resolver deployed with CodeS3Location each read
    back the exact JS of the S3 object they name, and a query through the pipeline returns the
    function's result."""
    cf = ctx.client("cloudformation")
    appsync = ctx.client("appsync")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-appsync-code-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    s3.put_object(Bucket=bucket, Key="func.js", Body=_FUNC_JS.encode("utf-8"))
    s3.put_object(Bucket=bucket, Key="resolver.js", Body=_RESOLVER_JS.encode("utf-8"))

    stack_name = ctx.unique_name("sim2real-appsync-s3code-")
    api_name = ctx.unique_name("sim2real-appsync-s3code-api-")
    created = cf.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template()),
        Parameters=[
            {"ParameterKey": "ApiName", "ParameterValue": api_name},
            {"ParameterKey": "CodeBucket", "ParameterValue": bucket},
        ],
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    status = _wait_stack(cf, stack_id, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})
    assert status == "CREATE_COMPLETE", f"stack {stack_id} ended {status!r}"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cf.describe_stacks(StackName=stack_id)["Stacks"][0].get("Outputs", [])
    }
    api_id = outputs["ApiId"]

    function = appsync.get_function(apiId=api_id, functionId=outputs["FunctionId"])[
        "functionConfiguration"
    ]
    assert function["code"] == _FUNC_JS, (
        f"expected the function's stored code to be exactly the S3 object uploaded; "
        f"got {function['code']!r}"
    )
    got = (function["functionId"], function["functionArn"])
    want = (outputs["FunctionId"], outputs["FunctionArn"])
    assert got == want, (
        f"GetAtt FunctionId/FunctionArn must match the function; expected {want!r}, got {got!r}"
    )

    resolver = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="s3CodeTest")[
        "resolver"
    ]
    assert resolver["code"] == _RESOLVER_JS, (
        f"expected the resolver's stored code to be exactly the S3 object uploaded; "
        f"got {resolver['code']!r}"
    )
    assert resolver["resolverArn"] == outputs["ResolverArn"], (
        f"GetAtt ResolverArn must match the resolver; "
        f"expected {outputs['ResolverArn']!r}, got {resolver['resolverArn']!r}"
    )

    status_code, body = _graphql_request(
        ctx, outputs["GraphQLUrl"], outputs["ApiKeyValue"], "query { s3CodeTest }"
    )
    assert status_code == 200, f"expected HTTP 200, got {status_code}: {body}"
    assert not body.get("errors"), f"expected no GraphQL errors, got {body.get('errors')}"
    assert body["data"]["s3CodeTest"] == "s3-function-result", (
        f"expected s3CodeTest == 's3-function-result', got {body['data']['s3CodeTest']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
