"""custom-error-response-rewrites-status-and-caches-for-error-caching-min-ttl."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "custom-error-response-rewrites-status-and-caches-for-error-caching-min-ttl"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

# Edge behaviour this check relies on (see BEAT 3 for the error-caching window):
#   - An OAC-signed S3 origin under an s3:GetObject-only grant may answer a missing key with 403
#     or 404, so both codes are configured below and the substitution and rewrite fire either way.
#   - CloudFront returns the custom page's bytes with the rewritten status 200.
#   - ErrorCachingMinTTL is a minimum CloudFront MAY hold the error for
#     (cloudfront#CustomErrorResponse$ErrorCachingMinTTL); an edge may serve the live object
#     sooner. Inside the TTL either the custom page or the live object is correct; once the TTL
#     has passed and the object exists at the origin, the live object must be served.
#   - No dedicated cache behaviour is needed for `/errors/*` when the error page lives on the
#     same origin.

#: An endpoint data-plane FAIL marker.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Managed CachingDisabled: successful responses are not cached, so every leg reaches the origin.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

#: Sent to CloudFront so the check exercises a genuinely nonzero ErrorCachingMinTTL. Not a quota —
#: a value this check chooses; the edge may hold the error for at most this long once recovered.
ERROR_CACHING_MIN_TTL = 30

#: Slack past ErrorCachingMinTTL for the edge to serve the recovered object (waits only).
RECOVERY_SLACK_S = 60.0

_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


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


# timing:real-time — ttl: 30 s https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/custom-error-pages-expiration.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A custom error response substitutes its page with the rewritten status 200; after the
    object appears at the origin the edge serves the page or the live object, and the live object
    once ErrorCachingMinTTL has passed.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cferr-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    error_page_key = "errors/404.html"
    error_page = b"<html><body>sim2real custom error page</body></html>"
    present_key = "present.txt"
    present_body = b"sim2real-object-that-exists"
    late_key = "arrives-late.txt"
    late_body = b"sim2real-object-that-arrives-after-the-first-error"

    s3.put_object(Bucket=bucket, Key=error_page_key, Body=error_page, ContentType="text/html")
    s3.put_object(Bucket=bucket, Key=present_key, Body=present_body, ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cferr-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    # Both 403 and 404 map to the same page: whichever code an OAC-signed S3 origin uses for a
    # missing key, the substitution and the rewrite are the same contract.
    custom_errors = [
        {"ErrorCode": code, "ResponsePagePath": f"/{error_page_key}", "ResponseCode": "200",
         "ErrorCachingMinTTL": ERROR_CACHING_MIN_TTL}
        for code in (403, 404)
    ]
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cferr-cr-"),
        "Comment": "sim2real custom error response and error caching",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "CustomErrorResponses": {"Quantity": len(custom_errors), "Items": custom_errors},
        "DefaultCacheBehavior": {
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
    _wait_distribution_deployed(cf, dist_id)

    # One keep-alive session: error caching is per POP, so every leg must land on the same one.
    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)

    # BEAT 1 — positive control.
    ok = _fetch_ok(session, f"{edge}/{present_key}")
    assert ok.content == present_body, (
        f"the positive control served the wrong bytes: expected {present_body!r}, got "
        f"{ok.content[:120]!r}"
    )

    # BEAT 2 — the missing object gets the custom page AND the rewritten status.
    errored = session.get(f"{edge}/{late_key}", timeout=15)
    error_observed_at = time.monotonic()
    assert errored.status_code == 200, (
        f"the custom error response must rewrite the origin's status: expected 200 (ResponseCode), "
        f"got {errored.status_code} / {errored.text[:200]!r}"
    )
    assert errored.content == error_page, (
        f"expected the custom error page {error_page!r}, got {errored.content[:200]!r}"
    )

    # BEAT 3 — the origin becomes healthy. ErrorCachingMinTTL is how long CloudFront may keep
    # serving the cached error (cloudfront#CustomErrorResponse$ErrorCachingMinTTL), so inside it
    # either body is correct; past it the live object must come back.
    s3.put_object(Bucket=bucket, Key=late_key, Body=late_body, ContentType="text/plain")
    head = s3.head_object(Bucket=bucket, Key=late_key)
    assert head["ContentLength"] == len(late_body), (
        f"the object must exist at the origin before this leg is meaningful: expected "
        f"ContentLength {len(late_body)}, got {head['ContentLength']}"
    )
    wait_s = max(0.0, error_observed_at + ERROR_CACHING_MIN_TTL - time.monotonic()) + RECOVERY_SLACK_S
    deadline = time.monotonic() + wait_s
    budget_end = time.monotonic() + _budget_s(ctx, wait_s)
    while True:
        recovered = session.get(f"{edge}/{late_key}", timeout=15)
        assert recovered.status_code == 200, (
            f"expected 200 (the live object or the rewritten error page), got "
            f"{recovered.status_code} / {recovered.text[:200]!r}"
        )
        assert recovered.content in (late_body, error_page), (
            f"expected the live object {late_body!r} or the cached custom page {error_page!r}, "
            f"got {recovered.content[:200]!r}"
        )
        if recovered.content == late_body or time.monotonic() >= deadline:
            break
        if time.monotonic() >= budget_end:
            # The runner's budget ends before the TTL and its slack do: no verdict on the target.
            raise TimeoutError(
                f"the check's time budget ran out {time.monotonic() - error_observed_at:.1f}s after "
                f"the error, before ErrorCachingMinTTL ({ERROR_CACHING_MIN_TTL}s) plus "
                f"{RECOVERY_SLACK_S:.0f}s had passed; recovery was not graded"
            )
        time.sleep(3.0)
    elapsed_when_recovered = time.monotonic() - error_observed_at
    assert recovered.content == late_body, (
        f"{elapsed_when_recovered:.1f}s after the error, past its {ERROR_CACHING_MIN_TTL}s "
        f"ErrorCachingMinTTL, the edge still serves the cached error page instead of the object "
        f"that exists at the origin"
    )

    # A consecutive read stays live; inside the TTL another edge host may still hold the error.
    recovered_again = session.get(f"{edge}/{late_key}", timeout=15)
    still_in_ttl = time.monotonic() - error_observed_at < ERROR_CACHING_MIN_TTL
    allowed = (late_body, error_page) if still_in_ttl else (late_body,)
    assert recovered_again.status_code == 200 and recovered_again.content in allowed, (
        f"the previous request already served the live object, but the next one returned "
        f"status {recovered_again.status_code} / {recovered_again.content[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
