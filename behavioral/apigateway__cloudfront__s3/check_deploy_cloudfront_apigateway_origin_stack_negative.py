"""deploy-cloudfront-apigateway-origin-stack-negative."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cloudfront-apigateway-origin-stack-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Of two distributions in one stack on the same API Gateway origin, the one without the stage OriginPath
    gets API Gateway's 403 passed through, while the one with OriginPath /prod reaches the mock integration."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    origin_cache_behavior = {
        "TargetOriginId": "apigw",
        "ViewerProtocolPolicy": "https-only",
        "AllowedMethods": ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"],
        "CachedMethods": ["GET", "HEAD"],
        # CachingDisabled + AllViewerExceptHostHeader is AWS's own recommended pairing for an
        # API Gateway origin (forwards everything except Host, never serves stale cached errors).
        "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
        "OriginRequestPolicyId": "b689b0a8-53d0-40ab-baf2-68738e2966ac",
    }
    custom_origin_config = {
        "OriginProtocolPolicy": "https-only",
        "OriginSSLProtocols": ["TLSv1.2"],
        "HTTPSPort": 443,
    }

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "RestApi": {
                    "Type": "AWS::ApiGateway::RestApi",
                    "Properties": {"Name": {"Fn::Sub": "${AWS::StackName}-api"}},
                },
                "EchoResource": {
                    "Type": "AWS::ApiGateway::Resource",
                    "Properties": {
                        "RestApiId": {"Ref": "RestApi"},
                        "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                        "PathPart": "echo",
                    },
                },
                "GetMethod": {
                    "Type": "AWS::ApiGateway::Method",
                    "Properties": {
                        "RestApiId": {"Ref": "RestApi"},
                        "ResourceId": {"Ref": "EchoResource"},
                        "HttpMethod": "GET",
                        "AuthorizationType": "NONE",
                        "Integration": {
                            "Type": "MOCK",
                            "RequestTemplates": {"application/json": '{"statusCode":200}'},
                            "IntegrationResponses": [
                                {
                                    "StatusCode": "200",
                                    "ResponseTemplates": {"application/json": '{"message":"ok"}'},
                                }
                            ],
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
                "DistMissingStage": {
                    "Type": "AWS::CloudFront::Distribution",
                    "Properties": {
                        "DistributionConfig": {
                            "Enabled": True,
                            "Origins": [
                                {
                                    "Id": "apigw",
                                    "DomainName": {"Fn::Sub": "${RestApi}.execute-api.${AWS::Region}.amazonaws.com"},
                                    "CustomOriginConfig": custom_origin_config,
                                }
                            ],
                            "DefaultCacheBehavior": origin_cache_behavior,
                        }
                    },
                },
                "DistWithStage": {
                    "Type": "AWS::CloudFront::Distribution",
                    "Properties": {
                        "DistributionConfig": {
                            "Enabled": True,
                            "Origins": [
                                {
                                    "Id": "apigw",
                                    "DomainName": {"Fn::Sub": "${RestApi}.execute-api.${AWS::Region}.amazonaws.com"},
                                    "OriginPath": "/prod",
                                    "CustomOriginConfig": custom_origin_config,
                                }
                            ],
                            "DefaultCacheBehavior": origin_cache_behavior,
                        }
                    },
                },
            },
            "Outputs": {
                "DistMissingId": {"Value": {"Ref": "DistMissingStage"}},
                "DistMissingDomain": {"Value": {"Fn::GetAtt": ["DistMissingStage", "DomainName"]}},
                "DistWithStageId": {"Value": {"Ref": "DistWithStage"}},
                "DistWithStageDomain": {"Value": {"Fn::GetAtt": ["DistWithStage", "DomainName"]}},
            },
        }
    )

    result = _deploy_cfn(ctx, template, teardown_deadline, timeout_s=600)
    outputs = result["outputs"]
    missing_id = outputs["DistMissingId"]
    missing_domain = outputs["DistMissingDomain"]
    with_id = outputs["DistWithStageId"]
    with_domain = outputs["DistWithStageDomain"]

    cf = ctx.client("cloudfront")
    for dist_id in (missing_id, with_id):
        _poll_until(
            lambda d=dist_id: cf.get_distribution(Id=d)["Distribution"]["Status"],
            lambda s: s == "Deployed",
            timeout_s=1800,
            interval_s=15.0,
            description=f"CloudFront distribution {dist_id} Deployed",
        )

    def _get(domain):
        try:
            base, route = ctx.endpoint_route(domain)
            req = urllib.request.Request(f"{base}/echo", headers=route)
            with urllib.request.urlopen(req, timeout=10, context=_https_context(ctx.http_verify)) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    # Negative: the origin has no stage in its path, so API Gateway can't route the request and
    # rejects it before the mock integration ever runs. The effect (the "ok" payload) must be
    # absent, not merely "some non-200".
    neg_status, neg_body = _poll_until(
        lambda: _get(missing_domain),
        lambda r: r[0] in (200, 403, 404),
        timeout_s=90,
        interval_s=5.0,
        description="origin fetch through distribution missing the stage path",
    )
    assert neg_status == 403
    assert b"ok" not in neg_body

    # Positive control: identical distribution config except OriginPath="/prod" -- the one
    # variable that was wrong above -- succeeds and actually reaches the mock integration.
    pos_status, pos_body = _poll_until(
        lambda: _get(with_domain),
        lambda r: r[0] == 200,
        timeout_s=90,
        interval_s=5.0,
        description="origin fetch through correctly-configured distribution",
    )
    assert pos_status == 200
    assert b"ok" in pos_body


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"
_CLEANUP_S = 1800.0


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


def _delete_stack_and_wait(ctx, stack_name: str, teardown_deadline) -> None:
    cfn = ctx.client("cloudformation")
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _CLEANUP_S - 120.0)
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

    # Deleting the stack's two distributions takes many minutes (each is disabled and propagated
    # first), so the wait spans the suite's whole cleanup budget.
    status = _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=max(deadline - time.monotonic(), 0.0),
        interval_s=2.0,
        description=f"delete stack {stack_name}",
    )
    if status == "DELETE_FAILED":
        raise AssertionError(f"delete stack {stack_name} ended DELETE_FAILED")


def _deploy_cfn(
    ctx, template, teardown_deadline, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
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
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, teardown_deadline))
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


def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) and verify else None)
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
