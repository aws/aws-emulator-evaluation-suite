"""deploy-distribution-serves-content-via-cloudformation."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "deploy-distribution-serves-content-via-cloudformation"
GROUP = "deploy"
SERVICES = ["cloudfront"]

_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"  # AWS managed "CachingDisabled"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed AWS::CloudFront::Distribution actually serves origin
    content over the live edge, not merely reaches CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    stack_name = ctx.unique_name("sim2real-cf-deploy-")
    bucket_name = ctx.unique_name("sim2real-cf-deploy-").lower()
    content_v1 = f"hello-from-{bucket_name}"

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(),
        Parameters=[{"ParameterKey": "BucketNameParam", "ParameterValue": bucket_name}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _destroy_stack(ctx, stack_name))

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1200}
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    domain_name = outputs["DistributionDomainName"]
    dist_id = outputs["DistributionId"]

    s3.put_object(Bucket=bucket_name, Key="index.html", Body=content_v1.encode(), ContentType="text/plain")

    _wait_distribution_deployed(cf, dist_id)

    edge, route = ctx.endpoint_route(domain_name)
    body = _poll_http_get(f"{edge}/index.html", route, timeout_s=240, verify=ctx.http_verify)
    assert body == content_v1, f"expected edge to serve {content_v1!r}, got {body!r}"


def _template() -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"BucketNameParam": {"Type": "String"}},
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": {"Ref": "BucketNameParam"},
                        "PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": True,
                            "BlockPublicPolicy": True,
                            "IgnorePublicAcls": True,
                            "RestrictPublicBuckets": True,
                        },
                    },
                },
                "OAC": {
                    "Type": "AWS::CloudFront::OriginAccessControl",
                    "Properties": {
                        "OriginAccessControlConfig": {
                            "Name": {"Ref": "BucketNameParam"},
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
                            "DefaultRootObject": "index.html",
                            "Origins": [
                                {
                                    "Id": "s3origin",
                                    "DomainName": {"Fn::GetAtt": ["Bucket", "RegionalDomainName"]},
                                    "OriginAccessControlId": {"Ref": "OAC"},
                                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                                }
                            ],
                            "DefaultCacheBehavior": {
                                "TargetOriginId": "s3origin",
                                "ViewerProtocolPolicy": "redirect-to-https",
                                "CachePolicyId": _CACHING_DISABLED_POLICY_ID,
                                "Compress": True,
                            },
                        }
                    },
                },
                "BucketPolicy": {
                    "Type": "AWS::S3::BucketPolicy",
                    "Properties": {
                        "Bucket": {"Ref": "Bucket"},
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "cloudfront.amazonaws.com"},
                                    "Action": "s3:GetObject",
                                    "Resource": {"Fn::Sub": "${Bucket.Arn}/*"},
                                    "Condition": {
                                        "StringEquals": {
                                            "AWS:SourceArn": {
                                                "Fn::Sub": "arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:distribution/${Distribution}"
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
                "DistributionDomainName": {"Value": {"Fn::GetAtt": ["Distribution", "DomainName"]}},
                "DistributionId": {"Value": {"Ref": "Distribution"}},
                "BucketNameOut": {"Value": {"Ref": "Bucket"}},
            },
        }
    )


# ===== helpers =====

def _wait_distribution_deployed(cf, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _poll_http_get(url: str, route: dict, timeout_s: float = 180.0, interval_s: float = 5.0, verify=True) -> str:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=route), timeout=10, context=_https_context(verify)) as resp:
                if resp.status == 200:
                    return resp.read().decode("utf-8")
                last_err = AssertionError(f"HTTP {resp.status}")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_err = exc
        time.sleep(interval_s)
    raise AssertionError(f"never got a 200 from {url} within {timeout_s}s (last error: {last_err})")


def _empty_bucket(s3, bucket: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _destroy_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    try:
        resources = cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ValidationError" and "does not exist" in err.get("Message", ""):
            return
        raise
    for res in resources:
        if res.get("ResourceType") == "AWS::S3::Bucket" and res.get("PhysicalResourceId"):
            _empty_bucket(s3, res["PhysicalResourceId"])
    cfn.delete_stack(StackName=stack_name)
    # Bounded by the suite's 1800 s cleanup budget; disabling and deleting a distribution fits it.
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 850}
    )


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
