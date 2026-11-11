"""cf-wildcard-invalidation-clears-only-matching-objects."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "cf-wildcard-invalidation-clears-only-matching-objects"
GROUP = 'invalidation'
SERVICES = ['cloudfront']

#: An endpoint data-plane FAIL marker.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
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

    DeleteDistribution issued immediately after the disabling UpdateDistribution is
    refused with ``DistributionNotDisabled``, so the second Deployed wait is mandatory rather than
    defensive. A distribution left enabled cannot be found by name later,
    because its id is server-minted.
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


def _fetch(session, url, *, timeout_s=180.0, interval_s=5.0):
    """GET ``url`` until it answers 200; DATAPLANE_MARKER on exhaustion."""
    last = None

    def probe():
        nonlocal last
        try:
            last = session.get(url, timeout=15)
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


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """An invalidation for /a/* evicts only /a/x at the edge, while /b/x on the same keep-alive
    session keeps serving its stale cached body (MinTTL 3600 rules out natural expiry).
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfinv-").lower()
    if ctx.region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 itself;
        # this literal is the API's own special case, not a pin away from ctx.region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    for k in ("a/x", "b/x"):
        s3.put_object(Bucket=bucket, Key=k, Body=b"version-1", ContentType="text/plain")

    policy_id = cf.create_cache_policy(CachePolicyConfig={
        "Name": ctx.unique_name("sim2real-behav-cfinv-cp-"),
        "Comment": "sim2real wildcard invalidation",
        "MinTTL": 3600, "DefaultTTL": 3600, "MaxTTL": 3600,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": False,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    })["CachePolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_cache_policy, cf.delete_cache_policy, policy_id))

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfinv-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    dist = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": {
            "CallerReference": ctx.unique_name("sim2real-behav-cfinv-cr-"),
            "Comment": "sim2real wildcard invalidation",
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
        },
        "Tags": {"Items": [{"Key": "sim2real-behav-check", "Value": CHECK}]},
    })["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    domain = dist["DomainName"]

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

    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)
    url_a, url_b = f"{edge}/a/x", f"{edge}/b/x"

    primed_a = _fetch(session, url_a).content
    primed_b = _fetch(session, url_b).content
    assert (primed_a, primed_b) == (b"version-1", b"version-1"), (
        f"priming failed — the edge did not serve the origin objects: {(primed_a, primed_b)!r}"
    )

    # Both paths must be genuinely CACHED before the invalidation, else "still stale" would be
    # vacuous. Polled on the edge's own X-Cache verdict rather than slept.
    for url in (url_a, url_b):
        xc = _poll_until(lambda u=url: session.get(u, timeout=15).headers.get("X-Cache"),
                         lambda x: x == "Hit from cloudfront",
                         timeout_s=120, interval_s=5,
                         description=f"a cache Hit on {url} before invalidating")
        assert xc == "Hit from cloudfront", f"{url} was never cached: X-Cache={xc!r}"

    for k in ("a/x", "b/x"):
        s3.put_object(Bucket=bucket, Key=k, Body=b"version-2", ContentType="text/plain")

    inv_id = cf.create_invalidation(
        DistributionId=dist_id,
        InvalidationBatch={"Paths": {"Quantity": 1, "Items": ["/a/*"]},
                           "CallerReference": ctx.unique_name("sim2real-behav-cfinv-i-")},
    )["Invalidation"]["Id"]
    inv_status = _poll_until(
        lambda: cf.get_invalidation(DistributionId=dist_id, Id=inv_id)["Invalidation"]["Status"],
        lambda s: s == "Completed",
        timeout_s=600, interval_s=5,
        description=f"invalidation {inv_id} to reach Completed",
    )
    assert inv_status == "Completed", f"the invalidation never completed: {inv_status!r}"

    after_a = session.get(url_a, timeout=15).content
    after_b = session.get(url_b, timeout=15).content

    assert after_a == b"version-2", (
        f"the invalidated path still serves stale content: {after_a!r} — /a/* did not evict /a/x"
    )
    assert after_b == b"version-1", (
        f"a NON-matching path was invalidated too: {after_b!r} — the /a/* wildcard over-matched "
        f"/b/x, whose entry has 3600s of MinTTL left"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
