"""e2e-distribution-webacl-association-blocks-request."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-distribution-webacl-association-blocks-request"
GROUP = "e2e"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Associating a Web ACL with a distribution actually blocks matching
    requests at the edge; disassociating restores normal origin serving."""
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    # WAFv2 Web ACLs scoped to CLOUDFRONT exist only in us-east-1, regardless of the runner
    # region — pin this client only, per Context.client's documented ACM/CloudFront idiom.
    waf = ctx.client("wafv2", region="us-east-1")

    bucket = _create_bucket(ctx)
    oac_id = _create_oac(ctx)
    dist_id, domain_name = _create_s3_distribution(ctx, bucket, oac_id)
    ctx.on_cleanup(lambda: _delete_oac(ctx, oac_id))
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))

    _attach_bucket_policy(ctx, bucket, dist_id)
    s3.put_object(Bucket=bucket, Key="index.html", Body=b"allowed-content", ContentType="text/plain")
    s3.put_object(Bucket=bucket, Key="blockme.html", Body=b"blocked-path-content", ContentType="text/plain")
    _wait_distribution_deployed(cf, dist_id)

    web_acl = waf.create_web_acl(
        Name=ctx.unique_name("sim2real-cf-waf-"),
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "default"},
        Rules=[
            {
                "Name": "block-blockme-path",
                "Priority": 0,
                "Statement": {
                    "ByteMatchStatement": {
                        "SearchString": "blockme",
                        "FieldToMatch": {"UriPath": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "CONTAINS",
                    }
                },
                "Action": {"Block": {}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "block-blockme",
                },
            }
        ],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Summary"]
    web_acl_arn = web_acl["ARN"]
    web_acl_id = web_acl["Id"]
    web_acl_name = web_acl["Name"]
    ctx.on_cleanup(lambda: _delete_web_acl(ctx, web_acl_name, web_acl_id))

    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.associate_distribution_web_acl(Id=dist_id, WebACLArn=web_acl_arn, IfMatch=etag)
    _wait_distribution_deployed(cf, dist_id)

    # Positive control: unaffected path still serves real content while the ACL is associated.
    edge, route = ctx.endpoint_route(domain_name)
    ok_body = _poll_http_get(f"{edge}/index.html", route, timeout_s=240, verify=ctx.http_verify)
    assert ok_body == "allowed-content", f"positive control: expected 'allowed-content', got {ok_body!r}"

    # The blocking rule must reject the matching path at the edge (never reaches origin).
    blocked_status = _poll_http_status(f"{edge}/blockme.html", route, expected=403, timeout_s=120, verify=ctx.http_verify)
    assert blocked_status == 403, f"expected HTTP 403 for the blocked path, got {blocked_status}"

    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=etag)
    _wait_distribution_deployed(cf, dist_id)

    # After disassociation, the same path is served normally again (real content, not a WAF block page).
    restored_body = _poll_http_get(f"{edge}/blockme.html", route, timeout_s=180, verify=ctx.http_verify)
    assert restored_body == "blocked-path-content", (
        f"expected real origin content after disassociation, got {restored_body!r}"
    )


# ===== helpers =====

def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cf-waf-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    return bucket


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_oac(ctx) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": ctx.unique_name("sim2real-cf-waf-oac-"),
            "OriginAccessControlOriginType": "s3",
            "SigningBehavior": "always",
            "SigningProtocol": "sigv4",
        }
    )
    return resp["OriginAccessControl"]["Id"]


def _delete_oac(ctx, oac_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
        cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchOriginAccessControl":
            raise


def _create_s3_distribution(ctx, bucket: str, oac_id: str) -> tuple[str, str]:
    cf = ctx.client("cloudfront")
    region = ctx.region
    regional_domain = f"{bucket}.s3.{region}.amazonaws.com"
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-cf-waf-cr-"),
            "Comment": "sim2real behavioral: webacl association",
            "Enabled": True,
            "DefaultRootObject": "index.html",
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "s3origin",
                        "DomainName": regional_domain,
                        "S3OriginConfig": {"OriginAccessIdentity": ""},
                        "OriginAccessControlId": oac_id,
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "s3origin",
                "ViewerProtocolPolicy": "redirect-to-https",
                "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # AWS managed CachingOptimized
            },
        }
    )
    dist = resp["Distribution"]
    return dist["Id"], dist["DomainName"]


def _attach_bucket_policy(ctx, bucket: str, dist_id: str) -> None:
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")
    dist_arn = cf.get_distribution(Id=dist_id)["Distribution"]["ARN"]
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]})
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudfront.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
            }
        ],
    }
    import json as _json

    s3.put_bucket_policy(Bucket=bucket, Policy=_json.dumps(policy))


def _wait_distribution_deployed(cf, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if cf.get_distribution(Id=dist_id)["Distribution"]["Status"] == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        config_resp = cf.get_distribution_config(Id=dist_id)
        config = config_resp["DistributionConfig"]
        etag = config_resp["ETag"]
        if config.get("Enabled"):
            config["Enabled"] = False
            etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
            _wait_distribution_deployed(cf, dist_id)
            etag = cf.get_distribution(Id=dist_id)["ETag"]
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFound",
            "NoSuchCachePolicy",
            "NoSuchContinuousDeploymentPolicy",
            "NoSuchDistribution",
            "NoSuchFieldLevelEncryptionConfig",
            "NoSuchOrigin",
            "NoSuchOriginRequestPolicy",
            "NoSuchRealtimeLogConfig",
            "NoSuchResponseHeadersPolicy",
            "TrustedKeyGroupDoesNotExist",
            "TrustedSignerDoesNotExist",
        ):
            raise


def _delete_web_acl(ctx, name: str, web_acl_id: str) -> None:
    waf = ctx.client("wafv2", region="us-east-1")
    # Retry while a disassociation propagates (WAFAssociatedItemException) or a concurrent edit
    # moved the lock token (WAFOptimisticLockException); raise anything else.
    deadline = time.monotonic() + 120
    while True:
        try:
            lock_token = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id)["LockToken"]
            waf.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id, LockToken=lock_token)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "WAFNonexistentItemException":
                return
            if code not in ("WAFAssociatedItemException", "WAFOptimisticLockException"):
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_http_get(url: str, route: dict, timeout_s: float = 180.0, interval_s: float = 5.0, verify=True) -> str:
    deadline = time.monotonic() + timeout_s
    last_err: Any = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=route), timeout=10, context=_https_context(verify)) as resp:
                if resp.status == 200:
                    return resp.read().decode("utf-8")
                last_err = AssertionError(f"HTTP {resp.status}")
        except urllib.error.HTTPError as exc:
            last_err = exc
        except (urllib.error.URLError, TimeoutError) as exc:
            last_err = exc
        time.sleep(interval_s)
    raise AssertionError(f"never got a 200 from {url} within {timeout_s}s (last error: {last_err})")


def _poll_http_status(url: str, route: dict, expected: int, timeout_s: float = 120.0, interval_s: float = 5.0, verify=True) -> int:
    deadline = time.monotonic() + timeout_s
    last_status: int | None = None
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(urllib.request.Request(url, headers=route), timeout=10, context=_https_context(verify))
            last_status = 200
        except urllib.error.HTTPError as exc:
            last_status = exc.code
            if last_status == expected:
                return last_status
        except (urllib.error.URLError, TimeoutError):
            last_status = None
        time.sleep(interval_s)
    raise AssertionError(f"never got HTTP {expected} from {url} within {timeout_s}s (last status: {last_status})")


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
