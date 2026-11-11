"""cfn-deploy-cloudfront-apigw-stack-positive."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "cfn-deploy-cloudfront-apigw-stack-positive"
GROUP = "deployment-order"
SERVICES = ["apigateway", "cloudfront", "s3"]

_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
_ALL_VIEWER_EXCEPT_HOST_HEADER_POLICY_ID = "b689b0a8-53d0-40ab-baf2-68738e2966ac"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN stack wiring a REST API behind a CloudFront custom origin serves the API's
    live MOCK-integration response through the distribution domain."""
    template = json.dumps(_template())
    deployed = _deploy_cfn(ctx, template, timeout_s=1500.0)
    domain = deployed["outputs"]["DistributionDomainName"]
    invoke_url = ctx.rest_api_url(deployed["outputs"]["ApiId"], "prod")

    # Positive control: the API itself answers directly, isolating what CloudFront adds.
    direct_status, direct_body = _poll_until(
        lambda: _http_get(ctx, invoke_url),
        lambda r: r[0] == 200,
        timeout_s=60.0,
        interval_s=3.0,
        description="direct API Gateway invoke URL responding",
    )
    assert direct_status == 200, f"expected direct invoke URL to answer 200, got {direct_status}"
    assert json.loads(direct_body) == {"message": "hello-from-apigw"}, (
        f"unexpected direct invoke body: {direct_body!r}"
    )

    def _fetch_via_cloudfront():
        url, headers = ctx.endpoint_route(f"{domain}/")
        return _http_get(ctx, url, headers=headers)

    status, content = _poll_until(
        _fetch_via_cloudfront,
        lambda r: r[0] == 200,
        timeout_s=240.0,
        interval_s=5.0,
        description="CloudFront proxying live API Gateway response",
    )
    assert status == 200, f"expected CloudFront to answer 200, got {status}"
    assert json.loads(content) == {"message": "hello-from-apigw"}, f"unexpected body: {content!r}"


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": {"Fn::Sub": "${AWS::StackName}-api"}},
            },
            "RootMethod": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "HttpMethod": "GET",
                    "AuthorizationType": "NONE",
                    "Integration": {
                        "Type": "MOCK",
                        "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                        "IntegrationResponses": [
                            {
                                "StatusCode": "200",
                                "ResponseTemplates": {
                                    "application/json": '{"message": "hello-from-apigw"}'
                                },
                            }
                        ],
                    },
                    "MethodResponses": [{"StatusCode": "200"}],
                },
            },
            "Deployment": {
                "Type": "AWS::ApiGateway::Deployment",
                "DependsOn": ["RootMethod"],
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
            "Distribution": {
                "Type": "AWS::CloudFront::Distribution",
                "DependsOn": ["Stage"],
                "Properties": {
                    "DistributionConfig": {
                        "Enabled": True,
                        "Origins": [
                            {
                                "Id": "ApiOrigin",
                                "DomainName": {
                                    "Fn::Sub": "${RestApi}.execute-api.${AWS::Region}.amazonaws.com"
                                },
                                "OriginPath": "/prod",
                                "CustomOriginConfig": {
                                    "HTTPPort": 80,
                                    "HTTPSPort": 443,
                                    "OriginProtocolPolicy": "https-only",
                                },
                            }
                        ],
                        "DefaultCacheBehavior": {
                            "TargetOriginId": "ApiOrigin",
                            "ViewerProtocolPolicy": "redirect-to-https",
                            "CachePolicyId": _CACHING_DISABLED_POLICY_ID,
                            "OriginRequestPolicyId": _ALL_VIEWER_EXCEPT_HOST_HEADER_POLICY_ID,
                            "AllowedMethods": ["GET", "HEAD", "OPTIONS"],
                        },
                    }
                },
            },
        },
        "Outputs": {
            "DistributionDomainName": {"Value": {"Fn::GetAtt": ["Distribution", "DomainName"]}},
            "ApiId": {"Value": {"Ref": "RestApi"}},
        },
    }


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
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
        timeout_s=1500,
        interval_s=10.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if hasattr(template, "read_text") else template
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
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _http_get(ctx, url: str, timeout: float = 10.0, headers: dict | None = None) -> tuple[int | None, str]:
    try:
        request = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(request, timeout=timeout, context=_ssl_context(ctx)) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        return None, str(e)


def _ssl_context(ctx):
    """The TLS context for this check's own call to the target, from ``ctx.http_verify``."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
