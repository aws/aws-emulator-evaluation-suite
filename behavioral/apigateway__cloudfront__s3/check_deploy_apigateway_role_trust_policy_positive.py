"""deploy-apigateway-role-trust-policy-positive."""
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

CHECK = "deploy-apigateway-role-trust-policy-positive"
GROUP = "iam-trust"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed IAM role trusting apigateway.amazonaws.com is actually ASSUMED by API
    Gateway's AWS-service integration to fetch an S3 object end-to-end (not merely created)."""
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": {"Fn::Sub": "${AWS::StackName}-bkt"}},
                },
                "ApiGatewayS3Role": {
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
                                "PolicyName": "S3GetObject",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "s3:GetObject",
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
                "ObjectResource": {
                    "Type": "AWS::ApiGateway::Resource",
                    "Properties": {
                        "RestApiId": {"Ref": "RestApi"},
                        "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                        "PathPart": "object",
                    },
                },
                "GetMethod": {
                    "Type": "AWS::ApiGateway::Method",
                    "Properties": {
                        "RestApiId": {"Ref": "RestApi"},
                        "ResourceId": {"Ref": "ObjectResource"},
                        "HttpMethod": "GET",
                        "AuthorizationType": "NONE",
                        "Integration": {
                            "Type": "AWS",
                            "IntegrationHttpMethod": "GET",
                            "Credentials": {"Fn::GetAtt": ["ApiGatewayS3Role", "Arn"]},
                            "Uri": {
                                "Fn::Sub": "arn:aws:apigateway:${AWS::Region}:s3:path/${Bucket}/hello.txt"
                            },
                            "IntegrationResponses": [{"StatusCode": "200"}],
                        },
                        "MethodResponses": [{"StatusCode": "200"}],
                    },
                },
                "Deployment": {
                    "Type": "AWS::ApiGateway::Deployment",
                    "DependsOn": "GetMethod",
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
    invoke_url = f"{ctx.rest_api_url(result['outputs']['ApiId'], 'prod')}/object"

    s3 = ctx.client("s3")
    body = f"hello-from-apigateway-{ctx.unique_name('x')}".encode()
    s3.put_object(Bucket=bucket, Key="hello.txt", Body=body)
    # The bucket has no DeletionPolicy, so CFN's DeleteBucket fails on the object we just put
    # unless we empty it first; registered after _deploy_cfn so LIFO runs this before the stack
    # delete.
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket))

    def _fetch():
        try:
            with urllib.request.urlopen(invoke_url, timeout=10, context=_ssl_context(ctx)) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    # IAM role propagation to API Gateway's assumed-role cache can lag briefly after creation.
    status, content = _poll_until(
        _fetch,
        lambda r: r[0] == 200,
        timeout_s=90,
        interval_s=3.0,
        description="API Gateway GET via assumed apigateway.amazonaws.com role",
    )
    assert status == 200, f"expected 200 from API Gateway S3 proxy GET, got {status}: {content!r}"
    assert content == body, f"expected proxied body {body!r}, got {content!r}"


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


def _empty_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


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
