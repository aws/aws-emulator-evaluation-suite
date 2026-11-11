"""cloudfront-s3-oai-legacy-access-positive."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudfront-s3-oai-legacy-access-positive"
GROUP = "origin-access-control"
SERVICES = ["apigateway", "cloudfront", "s3"]

_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A legacy CloudFront Origin Access Identity grants read access to a
    private S3 bucket via a bucket-policy statement whose Principal is the
    OAI's canonical ARN; the distribution can then serve the object."""
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    bucket = ctx.unique_name("sim2real-oai-")
    key = "index.txt"
    body = f"hello-from-oai-origin-{uuid.uuid4()}".encode()

    _create_private_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain")

    oai_id = _create_oai(ctx, cf, "sim2real behavioral check oai")

    origin_id = "s3-origin"
    dist_cfg = {
        "CallerReference": str(uuid.uuid4()),
        "Comment": "sim2real-oai-legacy-access-positive",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
                    "S3OriginConfig": {
                        "OriginAccessIdentity": f"origin-access-identity/cloudfront/{oai_id}"
                    },
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
            "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        }
    )["Distribution"]
    dist_id = dist["Id"]
    domain = dist["DomainName"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, cf, dist_id))

    _put_oai_bucket_policy_with_retry(ctx, s3, bucket, oai_id)

    _wait_distribution_deployed(ctx, cf, dist_id, timeout_s=1500.0)

    edge_url, edge_headers = ctx.endpoint_route(f"{domain}/{key}")
    status, fetched = _poll_http_get(
        edge_url,
        lambda s, b: s == 200,
        timeout_s=120.0,
        interval_s=10.0,
        headers=edge_headers,
        verify=ctx.http_verify,
    )
    assert status == 200, f"expected 200 fetching via CloudFront OAI origin, got {status}: {fetched!r}"
    assert fetched == body, "object content served through CloudFront OAI origin did not match what was written to S3"


def _put_oai_bucket_policy_with_retry(ctx, s3, bucket: str, oai_id: str, timeout_s: float = 60.0, interval_s: float = 5.0) -> None:
    """A freshly created OAI can take a few seconds to propagate into S3's
    principal-validation path; retry MalformedPolicy/InvalidPrincipal errors
    for a bounded window instead of failing on the very first attempt."""
    import botocore.exceptions

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            s3.put_bucket_policy(Bucket=bucket, Policy=_oai_bucket_policy(bucket, oai_id))
            return
        except botocore.exceptions.ClientError as exc:
            last_exc = exc
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("MalformedPolicy", "InvalidPrincipal"):
                raise
            time.sleep(interval_s)
    raise AssertionError(f"put_bucket_policy for OAI principal never succeeded within {timeout_s}s: {last_exc}")


def _create_private_bucket(ctx, s3, name: str) -> str:
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
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


def _create_oai(ctx, cf, comment: str) -> str:
    resp = cf.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig={
            "CallerReference": str(uuid.uuid4()),
            "Comment": comment,
        }
    )
    oai_id = resp["CloudFrontOriginAccessIdentity"]["Id"]

    def _cleanup():
        try:
            etag = cf.get_cloud_front_origin_access_identity(Id=oai_id)["ETag"]
            cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=etag)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchCloudFrontOriginAccessIdentity":
                raise

    ctx.on_cleanup(_cleanup)
    return oai_id


def _oai_bucket_policy(bucket: str, oai_id: str) -> str:
    import json

    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowCloudFrontOAI",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity {oai_id}"
                    },
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
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
    raise AssertionError(f"GET {url} never satisfied predicate within {timeout_s}s; last status={status}, body={body!r}")


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
