"""origin-group-fails-over-to-secondary-origin-at-the-edge."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "origin-group-fails-over-to-secondary-origin-at-the-edge"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

# An OAC-signed S3 origin may answer a missing key with 404 (NoSuchKey) or 403 (AccessDenied
# without s3:ListBucket), so both codes are failover criteria.

#: Marks a failure caused by an edge data plane that serves no traffic at all.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Managed CachingDisabled — an edge cache would let one leg's answer serve another leg's request.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

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
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment.

    Create -> Deployed and disable -> Deployed each take about three minutes; 900 s leaves wide margin.
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
    DistributionNotDisabled, so the second Deployed wait is mandatory rather than defensive.
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
# ===== end helpers =====


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An origin group serves the PRIMARY's bytes for a key both origins hold, the SECONDARY's bytes
    when the primary answers a failover code, and a 403 or 404 carrying neither object's bytes for a
    key neither holds.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    primary_bucket = ctx.unique_name("sim2real-behav-cffo-pri-").lower()
    secondary_bucket = ctx.unique_name("sim2real-behav-cffo-sec-").lower()
    for bucket in (primary_bucket, secondary_bucket):
        _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), primary_bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), secondary_bucket))

    shared_key = "on-primary.txt"
    failover_key = "only-on-secondary.txt"
    primary_body = b"sim2real-served-by-PRIMARY-origin"
    secondary_shadow = b"sim2real-served-by-SECONDARY-origin-shadow"
    secondary_body = b"sim2real-served-by-SECONDARY-origin-failover"

    s3.put_object(Bucket=primary_bucket, Key=shared_key, Body=primary_body,
                  ContentType="text/plain")
    # The SAME key in the secondary with different bytes: if the edge ever serves this, the
    # precedence leg fails loudly instead of passing by coincidence.
    s3.put_object(Bucket=secondary_bucket, Key=shared_key, Body=secondary_shadow,
                  ContentType="text/plain")
    s3.put_object(Bucket=secondary_bucket, Key=failover_key, Body=secondary_body,
                  ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cffo-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    def _s3_origin(origin_id, bucket):
        return {
            "Id": origin_id,
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }

    # 403 as well as 404: an OAC-signed principal granted only s3:GetObject may see S3 answer
    # AccessDenied instead of NoSuchKey for a missing key. Both are "the primary cannot serve it".
    failover_codes = [403, 404]
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cffo-cr-"),
        "Comment": "sim2real origin group failover at the edge",
        "Enabled": True,
        "Origins": {"Quantity": 2, "Items": [
            _s3_origin("primary-origin", primary_bucket),
            _s3_origin("secondary-origin", secondary_bucket),
        ]},
        "OriginGroups": {"Quantity": 1, "Items": [{
            "Id": "failover-group",
            "FailoverCriteria": {"StatusCodes": {"Quantity": len(failover_codes),
                                                 "Items": failover_codes}},
            "Members": {"Quantity": 2, "Items": [
                {"OriginId": "primary-origin"},
                {"OriginId": "secondary-origin"},
            ]},
        }]},
        "DefaultCacheBehavior": {
            # The behaviour targets the GROUP, which is the only legitimate case of a
            # TargetOriginId that is not an entry in Origins.
            "TargetOriginId": "failover-group",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_DISABLED,
        },
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    domain = dist["DomainName"]
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": _TAG_SET})

    for bucket in (primary_bucket, secondary_bucket):
        _allow_cloudfront_oac(s3, bucket, dist["ARN"])

    _wait_distribution_deployed(cf, dist_id)

    # One keep-alive session so all three legs are decided at the same POP in the same instant.
    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)

    served_primary = _fetch_ok(session, f"{edge}/{shared_key}")
    assert served_primary.content == primary_body, (
        f"the primary member must serve a key it holds: expected {primary_body!r}, got "
        f"{served_primary.content[:120]!r} (the secondary's shadow copy is "
        f"{secondary_shadow!r} — matching it means member order was ignored)"
    )

    failed_over = session.get(f"{edge}/{failover_key}", timeout=15)
    assert failed_over.status_code == 200, (
        f"origin failover did not happen: the primary cannot serve {failover_key!r} and the "
        f"secondary can, so expected 200, got {failed_over.status_code} / "
        f"{failed_over.text[:200]!r}"
    )
    assert failed_over.content == secondary_body, (
        f"expected the SECONDARY origin's bytes {secondary_body!r} after failover, got "
        f"{failed_over.content[:120]!r}"
    )

    absent = session.get(f"{edge}/on-neither.txt", timeout=15)
    assert absent.status_code in (403, 404), (
        f"a key held by NEITHER member must surface the last origin's refusal: expected 403 or "
        f"404, got {absent.status_code} / {absent.text[:200]!r}"
    )
    assert secondary_body not in absent.content and primary_body not in absent.content, (
        f"the refusal leaked another object's bytes: {absent.content[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
