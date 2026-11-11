"""deploy-cloudfront-distribution-serves-origin-content."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deploy-cloudfront-distribution-serves-origin-content"
GROUP = "deploy"
SERVICES = ["cloudfront"]

_CACHING_OPTIMIZED_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_OBJECT_KEY = "index.html"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFront distribution deployed through a CloudFormation stack (S3 bucket +
    origin access control + distribution + bucket policy) actually fetches and serves the
    object uploaded to its S3 origin over HTTPS -- not merely reaching CREATE_COMPLETE."""
    stack_name = ctx.unique_name("sim2real-behav-cfstack-")
    payload = f"sim2real-behavioral-payload-{stack_name}".encode("utf-8")

    template = _build_template()
    outputs = _deploy_cfn(ctx, stack_name, template)
    bucket_name = outputs["BucketName"]
    domain_name = outputs["DistributionDomainName"]

    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket_name, Key=_OBJECT_KEY, Body=payload, ContentType="text/plain")
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

    edge, route = ctx.endpoint_route(domain_name)
    fetched = _fetch_with_retries(f"{edge}/{_OBJECT_KEY}", route, timeout_s=240.0, verify=ctx.http_verify)
    assert fetched == payload, f"expected {payload!r} served via CloudFront, got {fetched!r}"


def _build_template() -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "OriginBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "Tags": [{"Key": "sim2real-check", "Value": {"Ref": "AWS::StackName"}}]
                },
            },
            "OAC": {
                "Type": "AWS::CloudFront::OriginAccessControl",
                "Properties": {
                    "OriginAccessControlConfig": {
                        "Name": {"Fn::Sub": "sim2real-oac-${AWS::StackName}"},
                        "OriginAccessControlOriginType": "s3",
                        "SigningBehavior": "always",
                        "SigningProtocol": "sigv4",
                    }
                },
            },
            "CFDistribution": {
                "Type": "AWS::CloudFront::Distribution",
                "Properties": {
                    "DistributionConfig": {
                        "Enabled": True,
                        "Comment": "sim2real behavioral deploy check",
                        "DefaultRootObject": _OBJECT_KEY,
                        "Origins": [
                            {
                                "Id": "s3origin",
                                "DomainName": {
                                    "Fn::GetAtt": ["OriginBucket", "RegionalDomainName"]
                                },
                                "S3OriginConfig": {"OriginAccessIdentity": ""},
                                "OriginAccessControlId": {"Fn::GetAtt": ["OAC", "Id"]},
                            }
                        ],
                        "DefaultCacheBehavior": {
                            "TargetOriginId": "s3origin",
                            "ViewerProtocolPolicy": "redirect-to-https",
                            "CachePolicyId": _CACHING_OPTIMIZED_POLICY_ID,
                        },
                    },
                    "Tags": [{"Key": "sim2real-check", "Value": {"Ref": "AWS::StackName"}}],
                },
            },
            "BucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "OriginBucket"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowCloudFrontServicePrincipal",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudfront.amazonaws.com"},
                                "Action": "s3:GetObject",
                                "Resource": {"Fn::Sub": "${OriginBucket.Arn}/*"},
                                "Condition": {
                                    "StringEquals": {
                                        "AWS:SourceArn": {
                                            "Fn::Sub": (
                                                "arn:aws:cloudfront::${AWS::AccountId}:"
                                                "distribution/${CFDistribution.Id}"
                                            )
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
            "DistributionDomainName": {"Value": {"Fn::GetAtt": ["CFDistribution", "DomainName"]}},
        },
    }


def _deploy_cfn(ctx, stack_name: str, template: dict) -> dict:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900})

    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert desc["StackStatus"] == "CREATE_COMPLETE", (
        f"stack did not complete: {desc['StackStatus']} {desc.get('StackStatusReason')}"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900})


def _empty_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        keys = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _fetch_with_retries(url: str, route: dict, *, timeout_s: float, verify=True) -> bytes:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=route), timeout=15, context=_https_context(verify)) as resp:
                return resp.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_err = exc
            time.sleep(2)
    raise AssertionError(f"could not fetch {url} within {timeout_s}s: {last_err}")


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
