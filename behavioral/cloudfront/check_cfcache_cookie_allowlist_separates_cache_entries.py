"""cfcache-cookie-allowlist-separates-cache-entries."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "cfcache-cookie-allowlist-separates-cache-entries"
GROUP = 'caching'
SERVICES = ['cloudfront']

#: Marks a failure caused by an edge data plane that serves no traffic at all.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: The one cookie in the cache key. ``other`` is deliberately NOT in it.
_KEYED_COOKIE = "sid"

#: TTLs that make an aged-out entry impossible inside this check: a Miss must mean a different cache
#: key, and a stale body must mean a cache hit.
_TTL = 3600


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
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment.

    Create -> Deployed and disable -> Deployed each typically take a few minutes; 900 s leaves a
    wide margin.
    """
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

    DeleteDistribution issued immediately after the disabling UpdateDistribution is refused with
    ``DistributionNotDisabled``, so the second Deployed wait is mandatory rather than defensive. A
    distribution left enabled cannot be found by name later, because its id is
    server-minted.
    """
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

    Marked with DATAPLANE_MARKER on exhaustion: the distribution is Deployed and the domain is the
    target's own, so a target that will not serve the object is a data-plane fidelity failure. The
    transport wording behind it ("Connection refused", "Read timed out") would otherwise read as
    OUR environment and drop out of the pass+fail denominator.
    """
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


# ===== check =====

@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A cache policy allowlisting one cookie keys on it alone: after the S3 object is rewritten, an
    added excluded cookie still gets the old bytes (same entry) while a changed allowlisted cookie
    gets the new ones, and the original entry stays intact.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfcook-").lower()
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "cookie-allowlist-separates-cache-entries"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

    key = "cookie.txt"
    v1 = b"sim2real-cookie-keyed-version-1"
    v2 = b"sim2real-cookie-keyed-version-2"
    s3.put_object(Bucket=bucket, Key=key, Body=v1, ContentType="text/plain")

    policy_id = cf.create_cache_policy(CachePolicyConfig={
        "Name": ctx.unique_name("sim2real-behav-cfcook-cp-"),
        "Comment": "sim2real cookie allowlist in the cache key",
        "MinTTL": _TTL, "DefaultTTL": _TTL, "MaxTTL": _TTL,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": False,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "whitelist",
                              "Cookies": {"Quantity": 1, "Items": [_KEYED_COOKIE]}},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    })["CachePolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_cache_policy, cf.delete_cache_policy,
                                             policy_id))

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfcook-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfcook-cr-"),
        "Comment": "sim2real cookie allowlist separates cache entries",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": policy_id,
        },
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted, so an unregistered
    # distribution cannot be found by name later.
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
    # so a Miss cannot be explained away by a second POP with a cold cache. The cookie is sent as an
    # explicit header rather than through a jar, so each request's key inputs are exactly stated.
    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)
    url = f"{edge}/{key}"
    alpha = {"Cookie": f"{_KEYED_COOKIE}=alpha"}
    alpha_plus_excluded = {"Cookie": f"{_KEYED_COOKIE}=alpha; other=zzz"}
    beta = {"Cookie": f"{_KEYED_COOKIE}=beta"}

    cold = _fetch(session, url, headers=alpha)
    assert cold.content == v1, (
        f"the cold sid=alpha fetch served {cold.content!r}, not the origin object {v1!r}"
    )
    warm = _poll_until(lambda: session.get(url, headers=alpha, timeout=15),
                       lambda r: r.headers.get("X-Cache") == "Hit from cloudfront",
                       timeout_s=120.0, interval_s=5.0,
                       description="the edge to hold a cached entry for sid=alpha")
    assert warm.content == v1, (
        f"the warm sid=alpha response served {warm.content!r}, not {v1!r}"
    )

    # Rewrite the origin and read the new bytes back from S3 itself. From here on the served body is
    # the evidence: v1 means the edge answered from its cache, v2 means it went to the origin.
    s3.put_object(Bucket=bucket, Key=key, Body=v2, ContentType="text/plain")
    origin_now = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert origin_now == v2, (
        f"the origin overwrite did not land, so nothing below is attributable to the cache key: "
        f"{origin_now!r}"
    )

    # The effect is ABSENT for a cookie outside the allowlist: exactly one thing changed — an extra
    # cookie that is not in the cache key — so the request must reuse the sid=alpha entry.
    excluded = session.get(url, headers=alpha_plus_excluded, timeout=15)
    assert excluded.status_code == 200, (
        f"adding an excluded cookie broke the request: {excluded.status_code!r} / "
        f"{excluded.text[:200]!r}"
    )
    assert excluded.content == v1, (
        f"a request differing only in the EXCLUDED cookie 'other' was served the rewritten origin "
        f"bytes {excluded.content!r} — the cache key wrongly includes 'other'"
    )
    assert excluded.headers.get("X-Cache") == "Hit from cloudfront", (
        f"a request differing only in the EXCLUDED cookie 'other' missed the cache: "
        f"X-Cache={excluded.headers.get('X-Cache')!r}"
    )

    # The effect: changing the ALLOWLISTED cookie is a different cache key, so this request must go
    # to the origin — polled for the new bytes to ARRIVE, never for how fast they do.
    fresh = _poll_until(lambda: session.get(url, headers=beta, timeout=15),
                        lambda r: r.status_code == 200 and r.content == v2,
                        timeout_s=120.0, interval_s=5.0,
                        description=(f"the sid=beta request to reach the origin and serve the "
                                     f"rewritten bytes {v2!r}"))
    assert fresh.content == v2, (
        f"a request differing in the ALLOWLISTED cookie {_KEYED_COOKIE!r} reused the sid=alpha "
        f"entry ({fresh.content!r}) — the cache key wrongly ignores {_KEYED_COOKIE!r}"
    )
    beta_warm = session.get(url, headers=beta, timeout=15)
    assert beta_warm.content == v2 and beta_warm.headers.get("X-Cache") == "Hit from cloudfront", (
        f"the sid=beta entry was never stored: {beta_warm.content!r} / "
        f"X-Cache={beta_warm.headers.get('X-Cache')!r}"
    )

    # Separation, not eviction: the original entry is still there, still holding the old bytes.
    alpha_again = session.get(url, headers=alpha, timeout=15)
    assert alpha_again.content == v1, (
        f"the sid=alpha entry was replaced by the sid=beta fetch: {alpha_again.content!r} — the two "
        f"cookie values must address independent cache entries"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
