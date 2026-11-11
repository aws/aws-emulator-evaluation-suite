"""cfcache-min-ttl-floors-origin-no-cache-directive."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "cfcache-min-ttl-floors-origin-no-cache-directive"
GROUP = 'caching'
SERVICES = ['cloudfront']

#: Tags an edge that never serves as a data-plane failure, so the transport error behind it is not
#: read as an environment problem.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Sent on both objects; CloudFront documents that MinTTL overrides `no-cache` and `max-age=0`.
_ORIGIN_CACHE_CONTROL = "no-cache, max-age=0"

#: MinTTL on the floored behaviour. The origin sends Cache-Control, so DefaultTTL never applies and
#: any cache reuse is due to MinTTL alone.
_FLOOR_TTL = 3600



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
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment.

    Create or disable typically takes 2-3 minutes to deploy; 900s leaves a wide margin."""
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Disable, wait for that change to deploy, then delete.

    DeleteDistribution right after the disabling update is refused with DistributionNotDisabled."""
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


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_bucket(s3, bucket, region) -> None:
    """us-east-1 is the one region create_bucket refuses a LocationConstraint for."""
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": region})


def _fetch(session, url, *, headers=None, timeout_s=180.0, interval_s=5.0):
    """GET ``url`` until it answers 200, then return that response.

    On exhaustion the error carries DATAPLANE_MARKER: a Deployed distribution must serve."""
    last = None

    def probe():
        nonlocal last
        try:
            last = session.get(url, headers=headers, timeout=15)
            return last
        except Exception as exc:  # noqa: BLE001 — transient during edge propagation; recorded
            last = exc
            return None

    try:
        return _poll_until(probe, lambda r: r is not None and r.status_code == 200,
                           timeout_s=timeout_s, interval_s=interval_s,
                           description=f"200 from {url}")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc


def _cache_policy(cf, ctx, name_prefix, *, min_ttl, default_ttl, max_ttl, comment):
    """A cache policy whose only interesting fields are its TTLs; nothing enters the key."""
    return cf.create_cache_policy(CachePolicyConfig={
        "Name": ctx.unique_name(name_prefix),
        "Comment": comment,
        "MinTTL": min_ttl, "DefaultTTL": default_ttl, "MaxTTL": max_ttl,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": False,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    })["CachePolicy"]["Id"]



@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A behaviour's MinTTL overrides the origin's ``no-cache``; a zero-TTL behaviour obeys it.

    After the S3 objects are overwritten, the zero-TTL path serves the new bytes and the floored
    path still serves the old ones.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfmin-").lower()
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "min-ttl-floors-origin-no-cache-directive"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

    floored_key = "floored.txt"
    control_key = "zerottl/control.txt"
    floored_v1 = b"sim2real-floored-version-1"
    control_v1 = b"sim2real-zerottl-version-1"
    floored_v2 = b"sim2real-floored-version-2"
    control_v2 = b"sim2real-zerottl-version-2"
    for key, body in ((floored_key, floored_v1), (control_key, control_v1)):
        s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain",
                      CacheControl=_ORIGIN_CACHE_CONTROL)

    floor_policy = _cache_policy(
        cf, ctx, "sim2real-behav-cfmin-floor-",
        min_ttl=_FLOOR_TTL, default_ttl=_FLOOR_TTL, max_ttl=_FLOOR_TTL,
        comment="sim2real MinTTL floors the origin directive")
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_cache_policy, cf.delete_cache_policy,
                                             floor_policy))
    zero_policy = _cache_policy(
        cf, ctx, "sim2real-behav-cfmin-zero-",
        min_ttl=0, default_ttl=0, max_ttl=0,
        comment="sim2real zero TTL obeys the origin directive")
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_cache_policy, cf.delete_cache_policy,
                                             zero_policy))

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfmin-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfmin-cr-"),
        "Comment": "sim2real MinTTL floors origin no-cache",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        # The default behaviour carries the MinTTL floor; one ordered behaviour carries the
        # zero-TTL control. One distribution, so the two arms differ in exactly one thing: the
        # cache policy. Two distributions would also differ in their edge state.
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": floor_policy,
        },
        "CacheBehaviors": {"Quantity": 1, "Items": [{
            "PathPattern": "/zerottl/*",
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": zero_policy,
        }]},
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted, so it cannot be found by
    # name later.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    domain = dist["DomainName"]
    cf.tag_resource(Resource=dist["ARN"],
                    Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]})

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipal",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist["ARN"]}},
        }],
    }))

    _wait_distribution_deployed(cf, dist_id)

    # ONE session for every request: keep-alive pins the TCP connection, and therefore the edge POP,
    # so a Miss cannot be explained away by a second POP with a cold cache.
    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)
    floored_url = f"{edge}/{floored_key}"
    control_url = f"{edge}/{control_key}"

    cold = _fetch(session, floored_url)
    assert cold.content == floored_v1, (
        f"the floored path served {cold.content!r} on a cold fetch, not the origin object "
        f"{floored_v1!r}"
    )
    warm = _poll_until(lambda: session.get(floored_url, timeout=15),
                       lambda r: r.headers.get("X-Cache") == "Hit from cloudfront",
                       timeout_s=120.0, interval_s=5.0,
                       description=(f"the floored path to report a cache Hit, which it must with "
                                    f"MinTTL={_FLOOR_TTL}s over an origin sending "
                                    f"{_ORIGIN_CACHE_CONTROL!r}"))
    assert warm.content == floored_v1, (
        f"the warm floored response served {warm.content!r}, not {floored_v1!r}"
    )

    control_cold = _fetch(session, control_url)
    assert control_cold.content == control_v1, (
        f"the zero-TTL control path served {control_cold.content!r} on a cold fetch, not "
        f"{control_v1!r}"
    )

    # Mutate the origin under BOTH behaviours, then read the new bytes back from S3 itself: from
    # here on, an edge response carrying the v1 bytes is positive evidence that the origin was not
    # contacted, and one carrying v2 is positive evidence that it was.
    for key, body in ((floored_key, floored_v2), (control_key, control_v2)):
        s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain",
                      CacheControl=_ORIGIN_CACHE_CONTROL)
    origin_now = {k: s3.get_object(Bucket=bucket, Key=k)["Body"].read()
                  for k in (floored_key, control_key)}
    assert origin_now == {floored_key: floored_v2, control_key: control_v2}, (
        f"the origin overwrite did not land, so nothing below is attributable to caching: "
        f"{origin_now!r}"
    )

    # Positive control FIRST: the zero-TTL behaviour obeys the origin's no-cache directive, so the
    # new bytes must ARRIVE there (polled for arrival, never for a deadline).
    control_fresh = _poll_until(lambda: session.get(control_url, timeout=15),
                                lambda r: r.status_code == 200 and r.content == control_v2,
                                timeout_s=120.0, interval_s=5.0,
                                description=(f"the zero-TTL path to serve the rewritten origin "
                                             f"bytes {control_v2!r}"))
    assert control_fresh.content == control_v2, (
        f"the zero-TTL path never reached the rewritten origin: {control_fresh.content!r}"
    )

    # The effect: with the origin demonstrably serving v2 and reachable through this very
    # distribution, the floored path must STILL answer v1 — MinTTL overrode `no-cache`.
    floored_after = session.get(floored_url, timeout=15)
    assert floored_after.status_code == 200, (
        f"the floored path stopped serving after the origin rewrite: "
        f"{floored_after.status_code!r} / {floored_after.text[:200]!r}"
    )
    assert floored_after.content == floored_v1, (
        f"the floored path served the rewritten origin bytes {floored_after.content!r} — a "
        f"behaviour with MinTTL={_FLOOR_TTL}s must keep the response it already has even though "
        f"the origin sent {_ORIGIN_CACHE_CONTROL!r}, and the zero-TTL control on the same "
        f"distribution proves the origin was reachable and had changed"
    )
    assert floored_after.headers.get("X-Cache") == "Hit from cloudfront", (
        f"the floored path served v1 but reported X-Cache={floored_after.headers.get('X-Cache')!r}"
        f" — v1 without a Hit means the edge answered from something other than its cache"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
