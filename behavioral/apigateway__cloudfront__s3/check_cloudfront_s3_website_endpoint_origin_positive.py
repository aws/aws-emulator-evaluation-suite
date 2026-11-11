"""cloudfront-s3-website-endpoint-origin-positive."""
from __future__ import annotations

import json
import secrets
import ssl
import time
import urllib.error
import urllib.request
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudfront-s3-website-endpoint-origin-positive"
GROUP = "origin-access-control"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CloudFront using an S3 static-website-hosting endpoint as a custom
    (HTTP) origin retrieves the configured index document's content when the
    viewer requests the distribution root."""
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    bucket = ctx.unique_name("sim2real-website-")
    token = str(uuid.uuid4())
    index_body = f"<html><body>Hello Website Origin {token}</body></html>".encode()
    # The bucket serves only requests whose Referer is this per-run secret; CloudFront sends it as
    # an origin custom header, so the website endpoint answers the distribution and no one else.
    referer = secrets.token_urlsafe(32)

    _create_website_bucket(ctx, s3, bucket, referer)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="index.html", Body=index_body, ContentType="text/html")

    website_domain = f"{bucket}.s3-website-{ctx.region}.amazonaws.com"
    origin_id = "s3-website-origin"
    dist_cfg = {
        "CallerReference": str(uuid.uuid4()),
        "Comment": "sim2real-website-endpoint-origin-positive",
        "Enabled": True,
        "DefaultRootObject": "index.html",
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": website_domain,
                    "CustomHeaders": {"Quantity": 1, "Items": [{"HeaderName": "Referer", "HeaderValue": referer}]},
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "http-only",
                        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
        },
    }
    dist = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": dist_cfg,
            "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
        }
    )["Distribution"]
    dist_id = dist["Id"]
    domain = dist["DomainName"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, cf, dist_id))

    _wait_distribution_deployed(ctx, cf, dist_id, timeout_s=1500.0)

    edge_url, edge_headers = ctx.endpoint_route(f"{domain}/")
    status, fetched = _poll_http_get(
        edge_url,
        lambda s, b: s == 200 and b == index_body,
        timeout_s=300.0,
        interval_s=10.0,
        headers=edge_headers,
        verify=ctx.http_verify,
    )
    assert status == 200, f"expected 200 fetching root via CloudFront website-endpoint origin, got {status}: {fetched!r}"
    assert fetched == index_body, "index document content served via CloudFront did not match the object written to S3"


def _create_website_bucket(ctx, s3, name: str, referer: str) -> str:
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, name))
    # S3 treats an aws:Referer-conditioned grant to "*" as a public policy, so only the two policy
    # blocks are lifted; ACLs stay blocked.
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    s3.put_bucket_website(
        Bucket=name,
        WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}},
    )
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadWithOriginReferer",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{name}/*",
                    "Condition": {"StringEquals": {"aws:Referer": referer}},
                }
            ],
        }
    )
    s3.put_bucket_policy(Bucket=name, Policy=policy)
    return name


def _empty_and_delete_bucket(ctx, s3, name: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _wait_distribution_deployed(ctx, cf, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s (last={status})")


def _disable_and_delete_distribution(ctx, cf, dist_id: str) -> None:
    try:
        resp = cf.get_distribution_config(Id=dist_id)
        cfg = resp["DistributionConfig"]
        etag = resp["ETag"]
        if cfg.get("Enabled"):
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, DistributionConfig=cfg, IfMatch=etag)
            _wait_distribution_deployed(ctx, cf, dist_id, timeout_s=1500.0)
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


def _http_get(url: str, timeout: float = 15.0, headers: dict[str, str] | None = None, verify=True):
    try:
        request = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(request, timeout=timeout, context=_https_context(verify)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        return None, str(e).encode()


def _poll_http_get(
    url: str, predicate, timeout_s: float = 180.0, interval_s: float = 10.0, headers: dict[str, str] | None = None, verify=True
):
    deadline = time.monotonic() + timeout_s
    status, body = None, b""
    while time.monotonic() < deadline:
        status, body = _http_get(url, headers=headers, verify=verify)
        if predicate(status, body):
            return status, body
        time.sleep(interval_s)
    return status, body


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
