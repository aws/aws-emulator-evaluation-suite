"""cloudfront-s3-oac-origin-access-positive."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudfront-s3-oac-origin-access-positive"
GROUP = "origin-access-control"
SERVICES = ["apigateway", "cloudfront", "s3"]

_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A distribution with an Origin Access Control serves objects from a bucket with Block Public Access on
    once the bucket policy grants the distribution-scoped CloudFront service principal access."""
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    bucket = ctx.unique_name("sim2real-oac-")
    key = "index.txt"
    body = f"hello-from-oac-origin-{uuid.uuid4()}".encode()

    _create_private_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain")

    oac_id = _create_oac(ctx, cf, ctx.unique_name("sim2real-oac-cfg-"))

    origin_id = "s3-origin"
    dist_cfg = {
        "CallerReference": str(uuid.uuid4()),
        "Comment": "sim2real-oac-origin-access-positive",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                    "OriginAccessControlId": oac_id,
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _CACHING_DISABLED_POLICY_ID,
        },
    }
    dist = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": dist_cfg,
            "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
        }
    )["Distribution"]
    dist_id = dist["Id"]
    dist_arn = dist["ARN"]
    domain = dist["DomainName"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, cf, dist_id))

    s3.put_bucket_policy(Bucket=bucket, Policy=_oac_bucket_policy(bucket, dist_arn))

    _wait_distribution_deployed(ctx, cf, dist_id, timeout_s=1500.0)

    edge_url, edge_headers = ctx.endpoint_route(f"{domain}/{key}")
    status, fetched = _poll_http_get(
        edge_url,
        lambda s, b: s == 200 and b == body,
        timeout_s=300.0,
        interval_s=10.0,
        headers=edge_headers,
        verify=ctx.http_verify,
    )
    assert status == 200, f"expected 200 fetching via CloudFront OAC origin, got {status}: {fetched!r}"
    assert fetched == body, "object content served through CloudFront OAC origin did not match what was written to S3"


def _create_private_bucket(ctx, s3, name: str) -> str:
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, name))
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


def _create_oac(ctx, cf, name: str) -> str:
    resp = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": name,
            "Description": "sim2real behavioral check",
            "SigningProtocol": "sigv4",
            "SigningBehavior": "always",
            "OriginAccessControlOriginType": "s3",
        }
    )
    oac_id = resp["OriginAccessControl"]["Id"]

    def _cleanup():
        try:
            etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
            cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchOriginAccessControl":
                raise

    ctx.on_cleanup(_cleanup)
    return oac_id


def _oac_bucket_policy(bucket: str, distribution_arn: str) -> str:
    import json

    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowCloudFrontServicePrincipalOAC",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudfront.amazonaws.com"},
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                    "Condition": {"StringEquals": {"AWS:SourceArn": distribution_arn}},
                }
            ],
        }
    )


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
