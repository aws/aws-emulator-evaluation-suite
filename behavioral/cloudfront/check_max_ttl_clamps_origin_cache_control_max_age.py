"""max-ttl-clamps-origin-cache-control-max-age."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "max-ttl-clamps-origin-cache-control-max-age"
GROUP = "policies"
SERVICES = ["cloudfront"]

#: Marks a failure caused by an edge data plane that serves no traffic at all.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: The origin's own freshness claim. Deliberately far above the clamped MaxTTL and equal to the
#: control's, so the ONLY thing that differs between the two paths is the cache policy.
ORIGIN_MAX_AGE = 3600
#: 5 s, not 1 s: the "immediate repeat must Hit" leg needs headroom for one HTTPS round trip, and a
#: 1 s cap would make that leg race the entry's own expiry and flake on a correct target.
_CLAMPED_MAX_TTL = 5
_KEPT_MAX_TTL = ORIGIN_MAX_AGE

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


def _fetch_ok(session, url, *, timeout_s=180.0, interval_s=5.0):
    """GET url until it answers 200, then return that response; raise (marked) on exhaustion."""
    last = None

    def probe():
        nonlocal last
        try:
            last = session.get(url, timeout=15)
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


def _cache_policy(cf, ctx, name_prefix, max_ttl):
    """A cache policy whose only interesting field is MaxTTL; nothing enters the key."""
    policy_id = cf.create_cache_policy(CachePolicyConfig={
        "Name": ctx.unique_name(name_prefix),
        "Comment": "sim2real MaxTTL clamp",
        # DefaultTTL == MaxTTL keeps the model's MinTTL <= DefaultTTL <= MaxTTL ordering satisfied
        # without introducing a third number: DefaultTTL applies only when the origin sends NO
        # Cache-Control, and this check's origin always sends one.
        "MinTTL": 0,
        "DefaultTTL": max_ttl,
        "MaxTTL": max_ttl,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": False,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    })["CachePolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_cache_policy, cf.delete_cache_policy,
                                             policy_id))
    return policy_id
# ===== end helpers =====


# timing:real-time — ttl: 5 s https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Expiration.html
@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """A cache behaviour's MaxTTL caps the origin's Cache-Control max-age: with identical max-age, the
    low-MaxTTL path stops being a Hit after at least its MaxTTL while the high-MaxTTL control path is
    still a Hit in the same instant.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfttl-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    body = b"sim2real-max-ttl-clamp-object"
    clamped_key = "clamped/obj.txt"
    kept_key = "kept/obj.txt"
    for key in (clamped_key, kept_key):
        # The origin's freshness claim is identical for both objects, so it cannot explain any
        # difference the edge shows.
        s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain",
                      CacheControl=f"max-age={ORIGIN_MAX_AGE}")

    clamped_policy = _cache_policy(cf, ctx, "sim2real-behav-cfttl-clamp-", _CLAMPED_MAX_TTL)
    kept_policy = _cache_policy(cf, ctx, "sim2real-behav-cfttl-keep-", _KEPT_MAX_TTL)

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfttl-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    behaviors = [
        {"PathPattern": "/clamped/*", "TargetOriginId": "s3origin",
         "ViewerProtocolPolicy": "allow-all", "CachePolicyId": clamped_policy},
        {"PathPattern": "/kept/*", "TargetOriginId": "s3origin",
         "ViewerProtocolPolicy": "allow-all", "CachePolicyId": kept_policy},
    ]
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfttl-cr-"),
        "Comment": "sim2real MaxTTL clamps origin Cache-Control",
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
            "CachePolicyId": kept_policy,
        },
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    domain = dist["DomainName"]
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": _TAG_SET})

    _allow_cloudfront_oac(s3, bucket, dist["ARN"])
    _wait_distribution_deployed(cf, dist_id)

    # ONE keep-alive session for every request: keep-alive pins the TCP connection and therefore the
    # edge POP, so neither a Miss nor a Hit can be explained by a second POP.
    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)
    clamped_url = f"{edge}/{clamped_key}"
    kept_url = f"{edge}/{kept_key}"

    # The clamped arm goes first and its repeat follows immediately, so the Hit leg cannot race the
    # 5 s cap it is there to establish. `stored_at` is taken the moment the entry was created.
    cold_clamped = _fetch_ok(session, clamped_url)
    stored_at = time.monotonic()
    warm_clamped = session.get(clamped_url, timeout=15)
    cold_kept = _fetch_ok(session, kept_url)
    warm_kept = session.get(kept_url, timeout=15)

    assert cold_clamped.content == body and cold_kept.content == body, (
        f"both arms must serve the origin object {body!r}, got "
        f"{cold_clamped.content[:60]!r} and {cold_kept.content[:60]!r}"
    )
    assert cold_clamped.headers.get("X-Cache") == "Miss from cloudfront", (
        f"the first request to the clamped path must be a cold Miss, got "
        f"{cold_clamped.headers.get('X-Cache')!r}"
    )
    assert cold_kept.headers.get("X-Cache") == "Miss from cloudfront", (
        f"the first request to the control path must be a cold Miss, got "
        f"{cold_kept.headers.get('X-Cache')!r}"
    )
    assert warm_clamped.headers.get("X-Cache") == "Hit from cloudfront", (
        f"the clamped path must cache for at least its MaxTTL of {_CLAMPED_MAX_TTL}s, so the "
        f"immediate repeat must Hit; got {warm_clamped.headers.get('X-Cache')!r} — without this the "
        f"expiry leg below would pass against a target that caches nothing"
    )
    assert warm_kept.headers.get("X-Cache") == "Hit from cloudfront", (
        f"the control path must Hit on the immediate repeat, got "
        f"{warm_kept.headers.get('X-Cache')!r}"
    )

    def clamped_probe():
        try:
            return session.get(clamped_url, timeout=15)
        except requests.RequestException as exc:  # transport only
            return exc

    expired = _poll_until(
        clamped_probe,
        lambda r: (isinstance(r, requests.Response)
                   and r.headers.get("X-Cache") != "Hit from cloudfront"),
        timeout_s=120.0, interval_s=2.0,
        description=(f"the clamped path to stop hitting once its MaxTTL of {_CLAMPED_MAX_TTL}s "
                     f"expires, even though the origin claimed max-age={ORIGIN_MAX_AGE}"),
    )
    clamped_after = time.monotonic() - stored_at
    x_cache = expired.headers.get("X-Cache")
    # A strict subset of CloudFront's X-Cache vocabulary: a revalidation against S3 that returns 304
    # is reported as RefreshHit, a full re-fetch as Miss. "Hit", "Error" and
    # "LambdaGeneratedResponse" are all excluded, so this set can still fail.
    assert x_cache in ("Miss from cloudfront", "RefreshHit from cloudfront"), (
        f"after MaxTTL={_CLAMPED_MAX_TTL}s the edge must go back to the origin: expected a Miss or "
        f"a RefreshHit, got {x_cache!r}"
    )
    assert expired.content == body, (
        f"the revalidated response must still be the origin object {body!r}, got "
        f"{expired.content[:60]!r}"
    )
    assert clamped_after >= _CLAMPED_MAX_TTL, (
        f"the clamped entry was dropped after {clamped_after:.1f}s but its MaxTTL is "
        f"{_CLAMPED_MAX_TTL}s — expiring EARLIER than the configured cap is its own divergence"
    )

    # The twin control, read in the same instant as the expiry above: same origin, same max-age,
    # same POP, MaxTTL=3600 — so it must NOT have expired.
    still_kept = session.get(kept_url, timeout=15)
    assert still_kept.headers.get("X-Cache") == "Hit from cloudfront", (
        f"{clamped_after:.1f}s in, the control path with MaxTTL={_KEPT_MAX_TTL}s and "
        f"max-age={ORIGIN_MAX_AGE} must still Hit; got "
        f"{still_kept.headers.get('X-Cache')!r} — a target that caps every entry at a second, or "
        f"caches nothing, fails here"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
