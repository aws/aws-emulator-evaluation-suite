"""e2e-invalidation-refreshes-stale-cached-object."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags


CHECK = "e2e-invalidation-refreshes-stale-cached-object"
GROUP = "e2e"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Create a distribution over an S3 origin, cache an object, mutate the origin, then
    invalidate the path -- the refetched object must reflect the new content, not merely
    have CreateInvalidation return 201."""
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    bucket = ctx.unique_name("sim2real-cf-inval-").replace("_", "-")
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; this is an S3 API
    # quirk, not a pinned target region -- ctx.region drives every other call in this check.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    oac_id = _create_oac(ctx)
    dist_id, etag, dist = _create_distribution(ctx, bucket_regional_domain=_bucket_domain(ctx, bucket), oac_id=oac_id)
    dist_arn = dist["ARN"]

    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=_bucket_policy_json(bucket, dist_arn),
    )

    resp = _wait_distribution_deployed(ctx, dist_id)
    domain = resp["Distribution"]["DomainName"]

    key = "invalidation-object.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"pre-invalidation-content", ContentType="text/plain")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    edge, route = ctx.endpoint_route(domain)
    url = f"{edge}/{key}"
    status, body = _poll_http_get(url, route, 200, timeout_s=90.0, verify=ctx.http_verify)
    assert status == 200 and body == b"pre-invalidation-content", (
        f"expected the first fetch through the distribution to serve the seeded object, "
        f"got status={status} body={body!r}"
    )

    # Confirm caching is actually active before relying on the TTL to hold it stale: the first
    # fetch above may have been the cold MISS that warms this edge, and a subsequent request
    # could land on a different, not-yet-warm PoP -- which would misread as "refreshed on its
    # own" below when it is really just a first-time MISS going straight to the (now-mutated)
    # origin.
    _, xcache_hit = _poll_until_header(url, route, "X-Cache", "Hit from cloudfront", timeout_s=90.0, verify=ctx.http_verify)

    # Mutate the origin -- with the long default TTL of CachingOptimized, this should stay
    # cached (stale) until we explicitly invalidate it.
    s3.put_object(Bucket=bucket, Key=key, Body=b"post-invalidation-content", ContentType="text/plain")
    status, body = _http_get(url, route, verify=ctx.http_verify)
    assert status == 200 and body == b"pre-invalidation-content", (
        "object refreshed on its own before invalidation; test setup doesn't isolate the "
        f"invalidation effect (status={status}, body={body!r}, prior X-Cache={xcache_hit!r})"
    )

    inval = cf.create_invalidation(
        DistributionId=dist_id,
        InvalidationBatch={
            "CallerReference": ctx.unique_name("sim2real-inval-"),
            "Paths": {"Quantity": 1, "Items": [f"/{key}"]},
        },
    )
    inval_id = inval["Invalidation"]["Id"]
    _wait_invalidation_completed(ctx, dist_id, inval_id)

    refreshed = False
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        status, body = _http_get(url, route, verify=ctx.http_verify)
        if status == 200 and body == b"post-invalidation-content":
            refreshed = True
            break
        time.sleep(5.0)
    assert refreshed, "invalidation completed but distribution never served the refreshed object"


def _bucket_domain(ctx, bucket: str) -> str:
    return f"{bucket}.s3.{ctx.region}.amazonaws.com"


def _bucket_policy_json(bucket: str, dist_arn: str) -> str:
    import json

    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudfront.amazonaws.com"},
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                    "Condition": {"StringEquals": {"aws:SourceArn": dist_arn}},
                }
            ],
        }
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _create_oac(ctx) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": ctx.unique_name("sim2real-oac-"),
            "OriginAccessControlOriginType": "s3",
            "SigningBehavior": "always",
            "SigningProtocol": "sigv4",
        }
    )
    oac_id = resp["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac(ctx, oac_id))
    return oac_id


def _delete_oac(ctx, oac_id: str) -> None:
    cf = ctx.client("cloudfront")
    etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
    cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)


def _create_distribution(ctx, bucket_regional_domain: str, oac_id: str):
    cf = ctx.client("cloudfront")
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-"),
        "Comment": "sim2real e2e-invalidation-refreshes-stale-cached-object",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "s3origin",
                    "DomainName": bucket_regional_domain,
                    "OriginAccessControlId": oac_id,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
        },
    }
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        }
    )
    dist = resp["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _teardown_distribution(ctx, dist_id))
    return dist_id, resp["ETag"], dist


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _teardown_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    config = cfg["DistributionConfig"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    resp = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])


def _wait_invalidation_completed(ctx, dist_id: str, inval_id: str, timeout_s: float = 600.0, interval_s: float = 10.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_invalidation(DistributionId=dist_id, Id=inval_id)
        if resp["Invalidation"]["Status"] == "Completed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"invalidation {inval_id} never reached Completed within {timeout_s}s")


def _http_get(url: str, route: dict, timeout: float = 10.0, verify=True):
    req = urllib.request.Request(url, headers={"User-Agent": "sim2real-behavioral-check", **route})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_https_context(verify)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError:
        return None, b""


def _poll_http_get(url: str, route: dict, expect_status: int, timeout_s: float = 60.0, interval_s: float = 3.0, verify=True):
    deadline = time.monotonic() + timeout_s
    last = (None, b"")
    while time.monotonic() < deadline:
        last = _http_get(url, route, verify=verify)
        if last[0] == expect_status:
            return last
        time.sleep(interval_s)
    return last


def _poll_until_header(url: str, route: dict, header: str, expect_value: str, timeout_s: float, interval_s: float = 3.0, verify=True):
    req = urllib.request.Request(url, headers={"User-Agent": "sim2real-behavioral-check", **route})
    deadline = time.monotonic() + timeout_s
    last_value = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(req, timeout=10.0, context=_https_context(verify)) as resp:
                last_value = resp.headers.get(header)
                if last_value == expect_value:
                    return resp.status, last_value
        except urllib.error.HTTPError as exc:
            last_value = exc.headers.get(header) if exc.headers else None
        except urllib.error.URLError:
            pass
        time.sleep(interval_s)
    raise AssertionError(
        f"never observed {header}={expect_value!r} from {url} within {timeout_s}s (last seen: {last_value!r})"
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
