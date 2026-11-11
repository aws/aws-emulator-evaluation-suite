"""cf-cache-key-querystring-allowlist-separates-cache-entries."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "cf-cache-key-querystring-allowlist-separates-cache-entries"
GROUP = 'policies'
SERVICES = ['cloudfront']

#: Marks a failure caused by an edge data plane that serves no traffic at all.
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
    """A cache policy that allowlists only ``v`` keys the edge cache on ``v`` alone: over one
    keep-alive session, varying an excluded parameter reuses the entry (X-Cache Hit) while varying
    ``v`` creates a new one.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfkey-").lower()
    # The cloudfront suite's harness region IS us-east-1 (the control plane is global and only
    # lives there), where create_bucket takes no LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    key = "obj.txt"
    body = b"sim2real-cache-key-object"
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain")
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "cache-key-querystring-allowlist-separates-cache-entries"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

    # MinTTL 3600 so nothing under test can expire naturally inside the check: a Miss must mean a
    # different cache key, never an aged-out entry.
    policy = cf.create_cache_policy(CachePolicyConfig={
        "Name": ctx.unique_name("sim2real-behav-cfkey-cp-"),
        "Comment": "sim2real cache-key querystring allowlist",
        "MinTTL": 3600, "DefaultTTL": 3600, "MaxTTL": 3600,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": False,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "whitelist",
                                   "QueryStrings": {"Quantity": 1, "Items": ["v"]}},
        },
    })["CachePolicy"]
    policy_id = policy["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_cache_policy, cf.delete_cache_policy, policy_id))

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfkey-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfkey-cr-"),
        "Comment": "sim2real cache-key querystring allowlist",
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

    # ONE session for all four requests: keep-alive pins the TCP connection, and therefore the edge
    # POP, so a Miss cannot be explained away by a second POP with a cold cache.
    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)
    base = f"{edge}/{key}"

    r1 = _fetch(session, f"{base}?v=1&junk=a")
    r2 = session.get(f"{base}?v=1&junk=b", timeout=15)
    r3 = session.get(f"{base}?v=2&junk=a", timeout=15)
    r4 = session.get(f"{base}?v=2&junk=a", timeout=15)
    x1, x2, x3, x4 = (r.headers.get("X-Cache") for r in (r1, r2, r3, r4))

    assert x1 == "Miss from cloudfront", f"the first request should be a cold Miss, got {x1!r}"
    assert x2 == "Hit from cloudfront", (
        f"a request differing only in the EXCLUDED query parameter missed the cache: "
        f"X-Cache={x2!r} — the cache key wrongly includes 'junk'"
    )
    assert x3 == "Miss from cloudfront", (
        f"a request differing in the ALLOWLISTED query parameter 'v' hit the cache: "
        f"X-Cache={x3!r} — the cache key wrongly ignores 'v'"
    )
    assert x4 == "Hit from cloudfront", (
        f"the repeat of the v=2 request missed: X-Cache={x4!r} — the v=2 entry was never stored"
    )
    assert [r.content for r in (r1, r2, r3, r4)] == [body] * 4, (
        f"served bodies diverged from the origin object: "
        f"{[r.content for r in (r1, r2, r3, r4)]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
