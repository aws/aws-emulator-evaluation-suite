"""deploy-cloudfront-s3-oac-stack-positive."""
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

CHECK = "deploy-cloudfront-s3-oac-stack-positive"
GROUP = "deployment-order"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """One stack creating the bucket, OAC, distribution and the distribution-scoped bucket policy serves the
    object through CloudFront while direct unauthenticated S3 access stays denied."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "OriginBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": {"Fn::Sub": "${AWS::StackName}-origin"}},
                },
                "OAC": {
                    "Type": "AWS::CloudFront::OriginAccessControl",
                    "Properties": {
                        "OriginAccessControlConfig": {
                            "Name": {"Fn::Sub": "${AWS::StackName}-oac"},
                            "OriginAccessControlOriginType": "s3",
                            "SigningBehavior": "always",
                            "SigningProtocol": "sigv4",
                        }
                    },
                },
                "Distribution": {
                    "Type": "AWS::CloudFront::Distribution",
                    "Properties": {
                        "DistributionConfig": {
                            "Enabled": True,
                            "Origins": [
                                {
                                    "Id": "s3origin",
                                    "DomainName": {"Fn::GetAtt": ["OriginBucket", "RegionalDomainName"]},
                                    "OriginAccessControlId": {"Fn::GetAtt": ["OAC", "Id"]},
                                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                                }
                            ],
                            "DefaultCacheBehavior": {
                                "TargetOriginId": "s3origin",
                                "ViewerProtocolPolicy": "redirect-to-https",
                                "AllowedMethods": ["GET", "HEAD"],
                                "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
                            },
                        }
                    },
                },
                "BucketPolicy": {
                    "Type": "AWS::S3::BucketPolicy",
                    "DependsOn": "Distribution",
                    "Properties": {
                        "Bucket": {"Ref": "OriginBucket"},
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "cloudfront.amazonaws.com"},
                                    "Action": "s3:GetObject",
                                    "Resource": {"Fn::Sub": "arn:aws:s3:::${OriginBucket}/*"},
                                    "Condition": {
                                        "StringEquals": {
                                            "AWS:SourceArn": {
                                                "Fn::Sub": "arn:aws:cloudfront::${AWS::AccountId}:distribution/${Distribution}"
                                            }
                                        }
                                    },
                                }
                            ],
                        },
                    },
                },
            },
            "Outputs": {
                "BucketName": {"Value": {"Ref": "OriginBucket"}},
                "DistributionId": {"Value": {"Ref": "Distribution"}},
                "DistributionDomainName": {"Value": {"Fn::GetAtt": ["Distribution", "DomainName"]}},
            },
        }
    )

    result = _deploy_cfn(ctx, template, teardown_deadline, timeout_s=600)
    bucket = result["outputs"]["BucketName"]
    dist_id = result["outputs"]["DistributionId"]
    domain = result["outputs"]["DistributionDomainName"]

    cf = ctx.client("cloudfront")
    _poll_until(
        lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
        lambda s: s == "Deployed",
        timeout_s=1800,
        interval_s=15.0,
        description=f"CloudFront distribution {dist_id} Deployed",
    )

    s3 = ctx.client("s3")
    key = "index.txt"
    body = f"oac-object-{ctx.unique_name('x')}".encode()
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    # CloudFormation refuses to delete a non-empty bucket, so this must be emptied before the
    # stack teardown that _deploy_cfn already registered; on_cleanup is LIFO, so registering it
    # here runs it first.
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    def _fetch_via_cf():
        try:
            base, route = ctx.endpoint_route(domain)
            req = urllib.request.Request(f"{base}/{key}", headers=route)
            with urllib.request.urlopen(req, timeout=10, context=_https_context(ctx.http_verify)) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    status, content = _poll_until(
        _fetch_via_cf,
        lambda r: r[0] == 200,
        timeout_s=120,
        interval_s=5.0,
        description="object served through CloudFront via OAC",
    )
    assert status == 200, f"expected 200 serving {key} via CloudFront {domain}, got {status}"
    assert content == body, f"expected body {body!r} served via CloudFront, got {content!r}"

    # Direct, unauthenticated S3 access must remain blocked: the bucket policy only trusts the
    # cloudfront.amazonaws.com principal scoped to this exact distribution's ARN.
    s3_endpoint = (ctx.client("s3").meta.endpoint_url or "").rstrip("/")

    def _fetch_direct():
        try:
            with urllib.request.urlopen(f"{s3_endpoint}/{bucket}/{key}", timeout=10, context=_https_context(ctx.http_verify)) as resp:
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code

    direct_status = _fetch_direct()
    assert direct_status == 403, (
        f"expected direct S3 access to {bucket}/{key} denied (403), got {direct_status}"
    )


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

    # Deleting the stack disables and deletes the CloudFront distribution, which takes minutes;
    # DELETE_FAILED is terminal, so it ends the wait and names the stuck stack.
    status = _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=max(deadline - time.monotonic(), 0.0),
        interval_s=2.0,
        description=f"delete stack {stack_name}",
    )
    if status == "DELETE_FAILED":
        raise AssertionError(f"delete stack {stack_name} ended in DELETE_FAILED")


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
