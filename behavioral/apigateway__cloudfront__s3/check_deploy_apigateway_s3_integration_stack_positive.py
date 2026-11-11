"""deploy-apigateway-s3-integration-stack-positive."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigateway-s3-integration-stack-positive"
GROUP = "deployment-order"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN stack wiring a greedy-path API Gateway AWS-service integration to S3 (via an IAM
    role) produces a genuinely working read/write proxy: PUT through the API lands the object
    in S3, and GET through the API returns exactly that content back."""
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": {"Fn::Sub": "${AWS::StackName}-bkt"}},
                },
                "ProxyRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "apigateway.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "S3ProxyAccess",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": ["s3:GetObject", "s3:PutObject"],
                                            "Resource": {"Fn::Sub": "arn:aws:s3:::${Bucket}/*"},
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "RestApi": {
                    "Type": "AWS::ApiGateway::RestApi",
                    "Properties": {"Name": {"Fn::Sub": "${AWS::StackName}-api"}},
                },
                "ProxyResource": {
                    "Type": "AWS::ApiGateway::Resource",
                    "Properties": {
                        "RestApiId": {"Ref": "RestApi"},
                        "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                        "PathPart": "{proxy+}",
                    },
                },
                "GetMethod": {
                    "Type": "AWS::ApiGateway::Method",
                    "Properties": {
                        "RestApiId": {"Ref": "RestApi"},
                        "ResourceId": {"Ref": "ProxyResource"},
                        "HttpMethod": "GET",
                        "AuthorizationType": "NONE",
                        "RequestParameters": {"method.request.path.proxy": True},
                        "Integration": {
                            "Type": "AWS",
                            "IntegrationHttpMethod": "GET",
                            "Credentials": {"Fn::GetAtt": ["ProxyRole", "Arn"]},
                            "Uri": {"Fn::Sub": "arn:aws:apigateway:${AWS::Region}:s3:path/${Bucket}/{proxy}"},
                            "RequestParameters": {"integration.request.path.proxy": "method.request.path.proxy"},
                            "IntegrationResponses": [{"StatusCode": "200"}],
                        },
                        "MethodResponses": [{"StatusCode": "200"}],
                    },
                },
                "PutMethod": {
                    "Type": "AWS::ApiGateway::Method",
                    "Properties": {
                        "RestApiId": {"Ref": "RestApi"},
                        "ResourceId": {"Ref": "ProxyResource"},
                        "HttpMethod": "PUT",
                        "AuthorizationType": "NONE",
                        "RequestParameters": {"method.request.path.proxy": True},
                        "Integration": {
                            "Type": "AWS",
                            "IntegrationHttpMethod": "PUT",
                            "Credentials": {"Fn::GetAtt": ["ProxyRole", "Arn"]},
                            "Uri": {"Fn::Sub": "arn:aws:apigateway:${AWS::Region}:s3:path/${Bucket}/{proxy}"},
                            "RequestParameters": {"integration.request.path.proxy": "method.request.path.proxy"},
                            "PassthroughBehavior": "WHEN_NO_MATCH",
                            "IntegrationResponses": [{"StatusCode": "200"}],
                        },
                        "MethodResponses": [{"StatusCode": "200"}],
                    },
                },
                "Deployment": {
                    "Type": "AWS::ApiGateway::Deployment",
                    "DependsOn": ["GetMethod", "PutMethod"],
                    "Properties": {"RestApiId": {"Ref": "RestApi"}},
                },
                "Stage": {
                    "Type": "AWS::ApiGateway::Stage",
                    "Properties": {
                        "RestApiId": {"Ref": "RestApi"},
                        "DeploymentId": {"Ref": "Deployment"},
                        "StageName": "prod",
                    },
                },
            },
            "Outputs": {
                "BucketName": {"Value": {"Ref": "Bucket"}},
                "ApiId": {"Value": {"Ref": "RestApi"}},
            },
        }
    )

    result = _deploy_cfn(ctx, template)
    bucket = result["outputs"]["BucketName"]
    base_url = ctx.rest_api_url(result["outputs"]["ApiId"], "prod")
    object_key = "proxy-object.txt"
    body = f"proxy-roundtrip-{ctx.unique_name('x')}".encode()

    # The bucket is a CFN-managed resource, so the stack's own DeleteBucket cannot succeed
    # while an object written through the proxy is still in it. Registered after _deploy_cfn's
    # delete_stack cleanup, this runs first (ctx.on_cleanup is LIFO) and empties the bucket
    # before CFN tries to delete it -- without this the stack teardown fails and both the
    # bucket and the stack leak on every run.
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    def _put_via_proxy():
        req = urllib.request.Request(f"{base_url}/{object_key}", data=body, method="PUT")
        try:
            with urllib.request.urlopen(req, timeout=10, context=_ssl_context(ctx)) as resp:
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code

    # IAM role propagation to API Gateway's assumed-role cache can lag briefly after creation.
    put_status = _poll_until(
        _put_via_proxy,
        lambda s: s == 200,
        timeout_s=90,
        interval_s=3.0,
        description="PUT object via API Gateway S3 proxy",
    )
    assert put_status == 200, f"expected 200 from PUT via API Gateway S3 proxy, got {put_status}"

    # Confirm the write actually landed in S3 -- not merely a 200 fabricated by API Gateway.
    s3 = ctx.client("s3")
    direct = s3.get_object(Bucket=bucket, Key=object_key)["Body"].read()
    assert direct == body, f"object landed in S3 does not match written body: got {direct!r}, expected {body!r}"

    def _get_via_proxy():
        try:
            with urllib.request.urlopen(f"{base_url}/{object_key}", timeout=10, context=_ssl_context(ctx)) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    status, content = _poll_until(
        _get_via_proxy,
        lambda r: r[0] == 200,
        timeout_s=30,
        interval_s=3.0,
        description="GET object via API Gateway S3 proxy",
    )
    assert content == body, f"proxied GET body mismatch: got {content!r}, expected {body!r}"


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _empty_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])


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


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
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
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
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


def _ssl_context(ctx):
    """The TLS context for this check's own call to the target, from ``ctx.http_verify``."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
