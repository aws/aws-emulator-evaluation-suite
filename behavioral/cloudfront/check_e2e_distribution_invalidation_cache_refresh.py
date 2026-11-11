"""e2e-distribution-invalidation-cache-refresh."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-distribution-invalidation-cache-refresh"
GROUP = "e2e"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """After an origin update a distribution keeps serving the stale cached object, and serves the
    updated one only once an invalidation completes; its private origin bucket admits only that
    distribution, through an origin access control."""
    s3 = ctx.client("s3")
    cloudfront = ctx.client("cloudfront")

    bucket = ctx.unique_name("sim2real-cf-inv-").lower().replace("_", "-")
    v1 = ctx.unique_name("sim2real-v1-")
    v2 = ctx.unique_name("sim2real-v2-")

    _create_private_bucket(ctx, bucket)
    s3.put_object(Bucket=bucket, Key="page.txt", Body=v1.encode("utf-8"), ContentType="text/plain")

    # A cache policy with a long-lived TTL so the response definitely stays cached until we
    # explicitly invalidate it (S3 doesn't send Cache-Control, so this TTL fully governs it).
    policy_name = ctx.unique_name("sim2real-cp-")
    policy = cloudfront.create_cache_policy(
        CachePolicyConfig={
            "Name": policy_name,
            "MinTTL": 300,
            "DefaultTTL": 3600,
            "MaxTTL": 86400,
            "ParametersInCacheKeyAndForwardedToOrigin": {
                "CookiesConfig": {"CookieBehavior": "none"},
                "HeadersConfig": {"HeaderBehavior": "none"},
                "QueryStringsConfig": {"QueryStringBehavior": "none"},
                "EnableAcceptEncodingGzip": False,
            },
        }
    )["CachePolicy"]
    policy_id = policy["Id"]
    ctx.on_cleanup(lambda: cloudfront.delete_cache_policy(
        Id=policy_id, IfMatch=cloudfront.get_cache_policy(Id=policy_id)["ETag"]
    ))

    oac_id = cloudfront.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": ctx.unique_name("sim2real-oac-"),
            "OriginAccessControlOriginType": "s3",
            "SigningBehavior": "always",
            "SigningProtocol": "sigv4",
        }
    )["OriginAccessControl"]["Id"]
    # Registered before the distribution's, so it runs after the distribution is gone.
    ctx.on_cleanup(lambda: _delete_oac(ctx, oac_id))

    origin_domain = f"{bucket}.s3.{ctx.region}.amazonaws.com"
    caller_ref = ctx.unique_name("sim2real-inv-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "invalidation e2e check",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "s3origin",
                    "DomainName": origin_domain,
                    "OriginAccessControlId": oac_id,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": policy_id,
        },
    }
    resp = cloudfront.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    domain = resp["Distribution"]["DomainName"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    cloudfront.tag_resource(
        Resource=resp["Distribution"]["ARN"],
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudfront.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringEquals": {"AWS:SourceArn": resp["Distribution"]["ARN"]}},
            }
        ],
    }))

    status = _poll_until(
        lambda: cloudfront.get_distribution(Id=dist_id)["Distribution"]["Status"],
        lambda s: s == "Deployed",
        timeout_s=1800,
        interval_s=20,
        timeout_msg=f"distribution {dist_id} never reached Deployed",
    )
    assert status == "Deployed", f"expected distribution {dist_id} Deployed, got {status!r}"

    url = f"http://{domain}/page.txt"
    first = _poll_fetch(ctx, url, expect_one_of=(v1,), timeout_s=300, interval_s=10)
    assert first == v1, f"expected initial fetch to return {v1!r}, got {first!r}"

    # Update the origin object without invalidating: CloudFront must keep serving the cached v1.
    s3.put_object(Bucket=bucket, Key="page.txt", Body=v2.encode("utf-8"), ContentType="text/plain")
    stale = _fetch(ctx, url)
    assert stale == v1, f"expected cached stale content {v1!r} before invalidation, got {stale!r}"

    inv_resp = cloudfront.create_invalidation(
        DistributionId=dist_id,
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": ["/page.txt"]},
            "CallerReference": ctx.unique_name("sim2real-inv-batch-"),
        },
    )
    inv_id = inv_resp["Invalidation"]["Id"]
    assert inv_resp["Invalidation"]["Status"] != "Completed", (
        f"expected a freshly created invalidation to be asynchronous, got immediate "
        f"Status={inv_resp['Invalidation']['Status']!r}"
    )

    inv_status = _poll_until(
        lambda: cloudfront.get_invalidation(DistributionId=dist_id, Id=inv_id)["Invalidation"]["Status"],
        lambda s: s == "Completed",
        timeout_s=300,
        interval_s=10,
        timeout_msg=f"invalidation {inv_id} never reached Completed",
    )
    assert inv_status == "Completed", f"expected invalidation {inv_id} Completed, got {inv_status!r}"

    fresh = _poll_fetch(ctx, url, expect_one_of=(v2,), timeout_s=180, interval_s=10)
    assert fresh == v2, f"expected refreshed content {v2!r} after invalidation, got {fresh!r}"


def _create_private_bucket(ctx, bucket: str) -> None:
    """A bucket with every Block Public Access setting on; only the distribution's grant opens it."""
    s3 = ctx.client("s3")
    kwargs = {}
    if ctx.region != "us-east-1":  # us-east-1 is the one region CreateBucket rejects a LocationConstraint for
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
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


def _delete_oac(ctx, oac_id: str) -> None:
    """Delete the OAC, waiting out the in-use window a just-deleted distribution leaves."""
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + 300
    while True:
        try:
            etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
            cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchOriginAccessControl":
                return
            if code != "OriginAccessControlInUse" or time.monotonic() > deadline:
                raise
        time.sleep(15)


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _disable_and_delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    config = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        got = cf.get_distribution(Id=dist_id)
        etag = got["ETag"]
        if got["Distribution"]["Status"] == "Deployed":
            break
        time.sleep(20)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, timeout_msg="condition never satisfied"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"{timeout_msg} within {timeout_s}s (last value: {value!r})")


def _fetch(ctx, url: str) -> str:
    _url, _route = ctx.endpoint_route(url)
    with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=10, context=_https_context(ctx.http_verify)) as resp:  # noqa: S310
        return resp.read().decode("utf-8")


def _poll_fetch(ctx, url: str, expect_one_of=(), timeout_s=120.0, interval_s=5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_body = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            last_body = _fetch(ctx, url)
            if not expect_one_of or last_body in expect_one_of:
                return last_body
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_err = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"never observed a response in {expect_one_of!r} from {url} within {timeout_s}s "
        f"(last body: {last_body!r}, last error: {last_err})"
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
