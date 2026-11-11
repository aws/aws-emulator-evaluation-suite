"""origin-request-policy-header-does-not-enter-the-cache-key."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "origin-request-policy-header-does-not-enter-the-cache-key"
GROUP = "policies"
SERVICES = ["cloudfront"]

#: Marks a failure caused by an edge data plane that serves no traffic at all.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_VARIANT_HEADER = "X-Sim-Variant"
#: MinTTL == DefaultTTL == MaxTTL, an hour: nothing under test can expire inside the check, so a
#: Miss must mean a different cache key and never an aged-out entry.
_TTL = 3600

_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=900.0, interval_s=10.0) -> str:
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment."""
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Disable, wait for that change to deploy, then delete."""
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


def _create_bucket(ctx, s3, bucket) -> None:
    # us-east-1 is the one region whose create_bucket takes no LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAG_SET})


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _allow_cloudfront_oac(s3, bucket, dist_arn) -> None:
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipal",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
        }],
    }))


def _fetch_ok(session, url, *, headers=None, timeout_s=180.0, interval_s=5.0):
    """GET url until it answers 200, then return that response; raise (marked) on exhaustion."""
    last = None

    def probe():
        nonlocal last
        try:
            last = session.get(url, headers=headers, timeout=15)
        except requests.RequestException as exc:  # transport only, during edge propagation
            last = exc
            return None
        return last

    try:
        return _poll_until(probe, lambda r: r is not None and r.status_code == 200,
                           timeout_s=timeout_s, interval_s=interval_s,
                           description=f"200 from {url}")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc


def _cache_policy(cf, ctx, name_prefix, header_behavior):
    """A cache policy that either keys on _VARIANT_HEADER or keys on nothing at all."""
    if header_behavior == "whitelist":
        headers_config = {"HeaderBehavior": "whitelist",
                          "Headers": {"Quantity": 1, "Items": [_VARIANT_HEADER]}}
    else:
        headers_config = {"HeaderBehavior": "none"}
    policy_id = cf.create_cache_policy(CachePolicyConfig={
        "Name": ctx.unique_name(name_prefix),
        "Comment": "sim2real cache key vs origin request policy",
        "MinTTL": _TTL, "DefaultTTL": _TTL, "MaxTTL": _TTL,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": False,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": headers_config,
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    })["CachePolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_cache_policy, cf.delete_cache_policy,
                                             policy_id))
    return policy_id
# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A header allowlisted only by the ORIGIN REQUEST policy does not split the cache (varying it
    Hits) while the same header in the cache policy does (Miss), each arm with a repeat-Hit control.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cforp-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    keyed_key = "keyed/obj.txt"
    forwarded_key = "forwarded/obj.txt"
    body = b"sim2real-origin-request-policy-object"
    for key in (keyed_key, forwarded_key):
        s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain")

    keyed_policy = _cache_policy(cf, ctx, "sim2real-behav-cforp-keyed-", "whitelist")
    forwarded_policy = _cache_policy(cf, ctx, "sim2real-behav-cforp-fwd-", "none")

    orp_id = cf.create_origin_request_policy(OriginRequestPolicyConfig={
        "Name": ctx.unique_name("sim2real-behav-cforp-orp-"),
        "Comment": "sim2real forwards the header without keying on it",
        "HeadersConfig": {"HeaderBehavior": "whitelist",
                          "Headers": {"Quantity": 1, "Items": [_VARIANT_HEADER]}},
        "CookiesConfig": {"CookieBehavior": "none"},
        "QueryStringsConfig": {"QueryStringBehavior": "none"},
    })["OriginRequestPolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_request_policy,
                                             cf.delete_origin_request_policy, orp_id))

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cforp-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    behaviors = [
        {"PathPattern": "/keyed/*", "TargetOriginId": "s3origin",
         "ViewerProtocolPolicy": "allow-all", "CachePolicyId": keyed_policy},
        {"PathPattern": "/forwarded/*", "TargetOriginId": "s3origin",
         "ViewerProtocolPolicy": "allow-all", "CachePolicyId": forwarded_policy,
         "OriginRequestPolicyId": orp_id},
    ]
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cforp-cr-"),
        "Comment": "sim2real origin request policy does not key the cache",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "CacheBehaviors": {"Quantity": len(behaviors), "Items": behaviors},
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": forwarded_policy,
        },
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    domain = dist["DomainName"]
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": _TAG_SET})

    _allow_cloudfront_oac(s3, bucket, dist["ARN"])
    _wait_distribution_deployed(cf, dist_id)

    # ONE keep-alive session: keep-alive pins the TCP connection and therefore the edge POP, so no
    # Miss can be explained by a second POP with a cold cache.
    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)
    keyed_url = f"{edge}/{keyed_key}"
    forwarded_url = f"{edge}/{forwarded_key}"
    variant_one = {_VARIANT_HEADER: "one"}
    variant_two = {_VARIANT_HEADER: "two"}

    # ARM A — the header IS a cache-key input.
    a_cold = _fetch_ok(session, keyed_url, headers=variant_one)
    a_varied = session.get(keyed_url, headers=variant_two, timeout=15)
    a_repeat = session.get(keyed_url, headers=variant_two, timeout=15)

    # ARM B — the header is forwarded only.
    b_cold = _fetch_ok(session, forwarded_url, headers=variant_one)
    b_varied = session.get(forwarded_url, headers=variant_two, timeout=15)

    assert a_cold.headers.get("X-Cache") == "Miss from cloudfront", (
        f"the first request to /{keyed_key} must be a cold Miss, got "
        f"{a_cold.headers.get('X-Cache')!r}"
    )
    assert a_varied.headers.get("X-Cache") == "Miss from cloudfront", (
        f"{_VARIANT_HEADER} is allowlisted by the CACHE policy on /keyed/*, so changing it must "
        f"produce a new cache entry: expected a Miss, got {a_varied.headers.get('X-Cache')!r} — the "
        f"cache key is ignoring a header the cache policy names"
    )
    assert a_repeat.headers.get("X-Cache") == "Hit from cloudfront", (
        f"the repeat of the variant-two request must Hit, got "
        f"{a_repeat.headers.get('X-Cache')!r} — without this the Miss above could just mean the "
        f"target caches nothing"
    )

    assert b_cold.headers.get("X-Cache") == "Miss from cloudfront", (
        f"the first request to /{forwarded_key} must be a cold Miss, got "
        f"{b_cold.headers.get('X-Cache')!r}"
    )
    assert b_varied.headers.get("X-Cache") == "Hit from cloudfront", (
        f"{_VARIANT_HEADER} is named ONLY by the origin request policy on /forwarded/*, so changing "
        f"it must reuse the existing cache entry: expected a Hit, got "
        f"{b_varied.headers.get('X-Cache')!r} — a target that conflates the cache policy with the "
        f"origin request policy splits the cache here and fragments it in production"
    )

    served = [r.content for r in (a_cold, a_varied, a_repeat, b_cold, b_varied)]
    assert served == [body] * 5, (
        f"every leg must serve the origin object {body!r}; got {[s[:40] for s in served]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
