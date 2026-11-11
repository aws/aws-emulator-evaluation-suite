"""deploy-cache-policy-cfn-ttl-enforced."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cache-policy-cfn-ttl-enforced"
GROUP = "deploy"
SERVICES = ["cloudfront"]


# timing:real-time — ttl: 12 s https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Expiration.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:deploy", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CloudFormation-deployed CachePolicy (MinTTL 12 s) attached to a distribution keeps serving the
    cached object right after the origin changes, though the origin's max-age is 1 s, and serves the
    new object once MinTTL has elapsed."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    policy_name = ctx.unique_name("sim2real-cp-")
    stack_name = ctx.unique_name("sim2real-cp-stack-")
    bucket_name = ctx.unique_name("sim2real-cp-bucket-").lower()
    min_ttl, default_ttl, max_ttl = 12, 123, 456
    origin_max_age = 1  # deliberately shorter than min_ttl, so MinTTL is the thing enforcing it
    key = "ttl-object.txt"

    template = {
        "Resources": {
            "Bucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": bucket_name,
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True,
                    },
                    "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
                },
            },
            "OAC": {
                "Type": "AWS::CloudFront::OriginAccessControl",
                "Properties": {
                    "OriginAccessControlConfig": {
                        "Name": bucket_name,
                        "OriginAccessControlOriginType": "s3",
                        "SigningBehavior": "always",
                        "SigningProtocol": "sigv4",
                    }
                },
            },
            "Policy": {
                "Type": "AWS::CloudFront::CachePolicy",
                "Properties": {
                    "CachePolicyConfig": {
                        "Name": policy_name,
                        "MinTTL": min_ttl,
                        "DefaultTTL": default_ttl,
                        "MaxTTL": max_ttl,
                        "ParametersInCacheKeyAndForwardedToOrigin": {
                            "CookiesConfig": {"CookieBehavior": "none"},
                            "HeadersConfig": {"HeaderBehavior": "none"},
                            "QueryStringsConfig": {"QueryStringBehavior": "none"},
                            "EnableAcceptEncodingGzip": False,
                        },
                    }
                },
            },
            "Dist": {
                "Type": "AWS::CloudFront::Distribution",
                "Properties": {
                    "DistributionConfig": {
                        "Enabled": True,
                        "Comment": "cache policy ttl enforcement check",
                        "Origins": [
                            {
                                "Id": "origin1",
                                "DomainName": {"Fn::GetAtt": ["Bucket", "RegionalDomainName"]},
                                "OriginAccessControlId": {"Ref": "OAC"},
                                "S3OriginConfig": {"OriginAccessIdentity": ""},
                            }
                        ],
                        "DefaultCacheBehavior": {
                            "TargetOriginId": "origin1",
                            "ViewerProtocolPolicy": "redirect-to-https",
                            "CachePolicyId": {"Ref": "Policy"},
                        },
                    },
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
                                            "Fn::Sub": "arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:distribution/${Dist}"
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
            "PolicyId": {"Value": {"Ref": "Policy"}},
            "DistId": {"Value": {"Ref": "Dist"}},
            "DomainName": {"Value": {"Fn::GetAtt": ["Dist", "DomainName"]}},
        },
    }

    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    _wait_stack_status(ctx, stack_name, "CREATE_COMPLETE", timeout_s=600)

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    policy_id = outputs["PolicyId"]
    dist_id = outputs["DistId"]
    domain = outputs["DomainName"]

    cloudfront = ctx.client("cloudfront")

    # Positive control: the policy and the distribution's reference to it are what we asked for.
    policy_cfg = cloudfront.get_cache_policy_config(Id=policy_id)["CachePolicyConfig"]
    assert policy_cfg["MinTTL"] == min_ttl, f"expected MinTTL={min_ttl}, got {policy_cfg['MinTTL']}"
    assert policy_cfg["DefaultTTL"] == default_ttl, (
        f"expected DefaultTTL={default_ttl}, got {policy_cfg['DefaultTTL']}"
    )
    assert policy_cfg["MaxTTL"] == max_ttl, f"expected MaxTTL={max_ttl}, got {policy_cfg['MaxTTL']}"

    dist_cfg = cloudfront.get_distribution_config(Id=dist_id)["DistributionConfig"]
    actual_policy_ref = dist_cfg["DefaultCacheBehavior"]["CachePolicyId"]
    assert actual_policy_ref == policy_id, (
        f"expected distribution's DefaultCacheBehavior.CachePolicyId={policy_id!r}, got {actual_policy_ref!r}"
    )

    _wait_distribution_deployed(cloudfront, dist_id, timeout_s=600.0)

    s3.put_object(Bucket=bucket_name, Key=key, Body=b"content-v1", CacheControl=f"max-age={origin_max_age}")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket_name, Key=key))

    edge, route = ctx.endpoint_route(domain)
    url = f"{edge}/{key}"
    status, body = _poll_http_get(url, route, expect_status=200, timeout_s=180.0, verify=ctx.http_verify)
    assert status == 200 and body == b"content-v1", (
        f"expected cold fetch 200 content-v1, got status={status} body={body!r}"
    )

    # Mutate the origin. The origin's own header says the object is stale after 1s, but the
    # cache policy's MinTTL=12s is a FLOOR CloudFront must enforce regardless -- the object must
    # still read as v1 for the next ~min_ttl seconds even though max-age has expired.
    s3.put_object(Bucket=bucket_name, Key=key, Body=b"content-v2", CacheControl=f"max-age={origin_max_age}")
    status, body = _http_get(url, route, verify=ctx.http_verify)
    assert status == 200 and body == b"content-v1", (
        f"expected MinTTL={min_ttl}s floor to hold origin's own max-age={origin_max_age}s stale, "
        f"got status={status} body={body!r} immediately after the origin mutation"
    )

    deadline = time.monotonic() + min_ttl + 90.0
    refreshed = False
    last_body = body
    while time.monotonic() < deadline:
        time.sleep(3.0)
        status, last_body = _http_get(url, route, verify=ctx.http_verify)
        if status == 200 and last_body == b"content-v2":
            refreshed = True
            break
    assert refreshed, (
        f"expected the distribution to serve refreshed content-v2 once MinTTL={min_ttl}s elapsed, "
        f"never observed it (last body={last_body!r})"
    )


def _wait_stack_status(ctx, stack_name, target_status, timeout_s=900.0, interval_s=15.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if status == target_status:
            return status
        if status.endswith("FAILED") or status == "ROLLBACK_COMPLETE":
            reasons = _stack_failure_reasons(cfn, stack_name)
            raise AssertionError(
                f"stack {stack_name} entered {status} while waiting for {target_status}: {reasons}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {target_status}, last status={status}")


def _stack_failure_reasons(cfn, stack_name: str) -> list[str]:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    return [
        f"{e['LogicalResourceId']}[{e['ResourceStatus']}]: {e.get('ResourceStatusReason', '')}"
        for e in events
    ]


def _wait_distribution_deployed(cloudfront, dist_id: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cloudfront.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s, last status={status}")


def _http_get(url: str, headers: dict, timeout: float = 10.0, verify=True):
    req = urllib.request.Request(url, headers={"User-Agent": "sim2real-behavioral-check", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_https_context(verify)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError:
        return None, b""


def _poll_http_get(url: str, headers: dict, expect_status: int, timeout_s: float = 60.0, interval_s: float = 3.0, verify=True):
    deadline = time.monotonic() + timeout_s
    last = (None, b"")
    while time.monotonic() < deadline:
        last = _http_get(url, headers, verify=verify)
        if last[0] == expect_status:
            return last
        time.sleep(interval_s)
    return last


def _delete_stack_and_wait(ctx, stack_name) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
            return
        time.sleep(20)


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
