"""cache-behavior-first-listed-match-wins-over-more-specific-pattern."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "cache-behavior-first-listed-match-wins-over-more-specific-pattern"
GROUP = "ordering"
SERVICES = ["cloudfront"]

#: Marks a failure caused by an edge data plane that serves no traffic at all.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Managed CachingDisabled: routing, not caching, is the subject — every request must be decided
#: fresh so no leg can be answered out of another leg's cache entry.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

_MARKER_HEADER = "X-Sim-Behavior"
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


def _marker_policy(cf, ctx, value):
    """A response headers policy whose only job is to stamp which behaviour handled the request."""
    policy_id = cf.create_response_headers_policy(ResponseHeadersPolicyConfig={
        "Name": ctx.unique_name(f"sim2real-behav-cford-{value}-"),
        "Comment": "sim2real cache behaviour ordering marker",
        "CustomHeadersConfig": {"Quantity": 1, "Items": [
            {"Header": _MARKER_HEADER, "Value": value, "Override": True},
        ]},
    })["ResponseHeadersPolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_response_headers_policy,
                                             cf.delete_response_headers_policy, policy_id))
    return policy_id
# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A request matching two cache behaviours is handled by the FIRST listed, not the most specific
    (the documented signed-URL hazard), shown by response-header markers, with a later-behaviour
    control and a default-behaviour leg whose header must be absent.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cford-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    overlap_key = "a/b/obj.txt"
    later_key = "c/obj.txt"
    default_key = "z/obj.txt"
    body = b"sim2real-cache-behavior-ordering-object"
    for key in (overlap_key, later_key, default_key):
        s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain")

    first_policy = _marker_policy(cf, ctx, "first")
    second_policy = _marker_policy(cf, ctx, "second")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cford-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    def _behavior(pattern, policy_id):
        return {
            "PathPattern": pattern,
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_DISABLED,
            "ResponseHeadersPolicyId": policy_id,
        }

    # ORDER IS THE SUBJECT: the broad pattern is listed BEFORE the specific one it subsumes.
    behaviors = [
        _behavior("/a/*", first_policy),
        _behavior("/a/b/*", second_policy),
        _behavior("/c/*", second_policy),
    ]
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cford-cr-"),
        "Comment": "sim2real cache behaviour first-match-wins",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "CacheBehaviors": {"Quantity": len(behaviors), "Items": behaviors},
        "DefaultCacheBehavior": {
            # No ResponseHeadersPolicyId: the absent header is what makes the default leg gradeable.
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_DISABLED,
        },
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    domain = dist["DomainName"]
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": _TAG_SET})

    _allow_cloudfront_oac(s3, bucket, dist["ARN"])

    # The stored order must survive the round trip before the edge legs mean anything: if the
    # service reordered the list, "first match" would be about a list this check never wrote.
    stored = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    stored_patterns = [b["PathPattern"] for b in stored["CacheBehaviors"]["Items"]]
    assert stored_patterns == ["/a/*", "/a/b/*", "/c/*"], (
        f"expected the behaviours stored in the order written ['/a/*', '/a/b/*', '/c/*'], got "
        f"{stored_patterns}"
    )

    _wait_distribution_deployed(cf, dist_id)

    # One keep-alive session: all three legs are decided at the same POP in the same instant.
    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)

    later = _fetch_ok(session, f"{edge}/{later_key}")
    assert later.content == body, (
        f"the control leg served the wrong bytes: expected {body!r}, got {later.content[:60]!r}"
    )
    assert later.headers.get(_MARKER_HEADER) == "second", (
        f"a behaviour past index 0 must be reachable and its response headers policy applied: "
        f"expected {_MARKER_HEADER}='second' for /{later_key}, got "
        f"{later.headers.get(_MARKER_HEADER)!r}"
    )

    overlap = session.get(f"{edge}/{overlap_key}", timeout=15)
    assert overlap.status_code == 200, (
        f"expected 200 for /{overlap_key}, got {overlap.status_code} / {overlap.text[:200]!r}"
    )
    assert overlap.headers.get(_MARKER_HEADER) == "first", (
        f"/{overlap_key} matches '/a/*' at index 0 and '/a/b/*' at index 1, and CloudFront applies "
        f"the FIRST match: expected {_MARKER_HEADER}='first', got "
        f"{overlap.headers.get(_MARKER_HEADER)!r} — 'second' means the target resolved the most "
        f"specific pattern instead of the first listed one"
    )

    fallback = session.get(f"{edge}/{default_key}", timeout=15)
    assert fallback.status_code == 200, (
        f"expected 200 for /{default_key}, got {fallback.status_code} / {fallback.text[:200]!r}"
    )
    assert _MARKER_HEADER not in fallback.headers, (
        f"/{default_key} matches no listed pattern, so the default behaviour handles it and no "
        f"response headers policy applies: expected {_MARKER_HEADER} absent, got "
        f"{fallback.headers.get(_MARKER_HEADER)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
