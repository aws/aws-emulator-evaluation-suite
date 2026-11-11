"""deploy-cache-policy-enforced-via-cloudformation."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "deploy-cache-policy-enforced-via-cloudformation"
GROUP = "deploy"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed Distribution enforces its CachePolicy's cache key on live requests (query
    strings excluded), seen in the edge's X-Cache header and body, not merely in the config."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    stack_name = ctx.unique_name("sim2real-cf-cp-")
    bucket_name = ctx.unique_name("sim2real-cf-cp-").lower()
    cache_policy_name = ctx.unique_name("sim2real-cf-cp-policy-")
    content = f"cache-key-test-{bucket_name}"

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(),
        Parameters=[
            {"ParameterKey": "BucketNameParam", "ParameterValue": bucket_name},
            {"ParameterKey": "CachePolicyNameParam", "ParameterValue": cache_policy_name},
        ],
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
    cache_policy_id = outputs["CachePolicyId"]

    # Config-presence check (the cheap part): the distribution really references our policy.
    config = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    assert config["DefaultCacheBehavior"]["CachePolicyId"] == cache_policy_id

    s3.put_object(Bucket=bucket_name, Key="index.html", Body=content.encode(), ContentType="text/plain")
    _wait_distribution_deployed(cf, dist_id)

    edge, route = ctx.endpoint_route(domain_name)
    url_base = f"{edge}/index.html"

    # Warm the cache at whichever edge POP our client is routed to: keep
    # requesting the SAME query string until we observe a real cache Hit
    # (the first request is expected to be a cold Miss; a repeat hit proves
    # the object is actually cached at that POP before we test the cache key).
    body1, xcache1 = _poll_until_header(f"{url_base}?v=1", route, "X-Cache", "Hit from cloudfront", timeout_s=240, verify=ctx.http_verify)
    assert body1 == content

    # A DIFFERENT query string must hit the SAME cache entry (same POP, same
    # object) because our custom cache policy's QueryStringsConfig excludes
    # query strings from the cache key -- this is the actual policy-enforced
    # behavior under test, not just config presence.
    #
    # This MUST be a single, non-retried request: a target whose cache key wrongly
    # includes the query string would also Miss-then-self-warm to a Hit on a retried
    # ?v=2 request (its own second identical request would hit its own freshly-created
    # entry), which would make a polling read indistinguishable from the correct
    # behavior it's supposed to catch. Only a Hit on the FIRST ?v=2 request proves the
    # entry was already there -- i.e. that it's the SAME entry ?v=1 warmed.
    body2, xcache2 = _http_get_once(f"{url_base}?v=2", route, verify=ctx.http_verify)
    assert body2 == content
    assert xcache2 == "Hit from cloudfront", (
        f"expected the cache-policy's query-string-exclusion to produce an immediate Hit "
        f"on the first ?v=2 request (reusing the ?v=1 entry), got X-Cache={xcache2!r}"
    )



def _template() -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "BucketNameParam": {"Type": "String"},
                "CachePolicyNameParam": {"Type": "String"},
            },
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
                "CachePolicy": {
                    "Type": "AWS::CloudFront::CachePolicy",
                    "Properties": {
                        "CachePolicyConfig": {
                            "Name": {"Ref": "CachePolicyNameParam"},
                            "DefaultTTL": 300,
                            "MaxTTL": 300,
                            "MinTTL": 300,
                            "ParametersInCacheKeyAndForwardedToOrigin": {
                                "CookiesConfig": {"CookieBehavior": "none"},
                                "HeadersConfig": {"HeaderBehavior": "none"},
                                "QueryStringsConfig": {"QueryStringBehavior": "none"},
                                "EnableAcceptEncodingGzip": False,
                                "EnableAcceptEncodingBrotli": False,
                            },
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
                                "CachePolicyId": {"Ref": "CachePolicy"},
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
                "CachePolicyId": {"Value": {"Ref": "CachePolicy"}},
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


def _poll_until_header(
    url: str, route: dict, header: str, expected_value: str, timeout_s: float = 180.0, interval_s: float = 5.0, verify=True
) -> tuple[str, str]:
    deadline = time.monotonic() + timeout_s
    last_body, last_val, last_err = "", "", None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=route), timeout=10, context=_https_context(verify)) as resp:
                if resp.status == 200:
                    last_body = resp.read().decode("utf-8")
                    last_val = resp.headers.get(header, "")
                    if last_val == expected_value:
                        return last_body, last_val
                else:
                    last_err = AssertionError(f"HTTP {resp.status}")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_err = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"never observed {header}={expected_value!r} from {url} within {timeout_s}s "
        f"(last {header}={last_val!r}, last error: {last_err})"
    )


def _http_get_once(url: str, route: dict, verify=True) -> tuple[str, str]:
    with urllib.request.urlopen(urllib.request.Request(url, headers=route), timeout=10, context=_https_context(verify)) as resp:
        return resp.read().decode("utf-8"), resp.headers.get("X-Cache", "")


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
