"""cfcache-conditional-get-304-only-for-the-matching-etag."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "cfcache-conditional-get-304-only-for-the-matching-etag"
GROUP = 'caching'
SERVICES = ['cloudfront']

#: Marks a failure caused by an edge data plane that serves no traffic at all.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: A syntactically valid entity tag that cannot be the object's: S3 mints ETags as quoted hex MD5
#: digests, so no object can ever carry this one.
_WRONG_ETAG = '"sim2real-not-the-etag-of-any-object"'

#: TTLs that make the whole check happen inside one cached entry: a second fetch that misses would
#: mean a different cache key or an aged-out entry, never a conditional-request decision.
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

@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The edge answers 304 for the cached object's own ETag and a full 200 with the object's bytes
    for any other validator, so an edge that answers 304 to every conditional GET fails.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfcond-").lower()
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "conditional-get-304-only-for-the-matching-etag"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

    key = "conditional.txt"
    body = b"sim2real-conditional-get-object-bytes"
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain")

    policy_id = cf.create_cache_policy(CachePolicyConfig={
        "Name": ctx.unique_name("sim2real-behav-cfcond-cp-"),
        "Comment": "sim2real conditional GET",
        "MinTTL": _TTL, "DefaultTTL": _TTL, "MaxTTL": _TTL,
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

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfcond-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfcond-cr-"),
        "Comment": "sim2real conditional GET 304 only for the matching ETag",
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
    # so the entry the validator is compared against is the entry the first request established.
    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)
    url = f"{edge}/{key}"

    cold = _fetch(session, url)
    assert cold.content == body, (
        f"the cold fetch served {cold.content!r}, not the origin object {body!r}"
    )
    etag = cold.headers.get("ETag")
    assert etag and etag.startswith('"') and etag.endswith('"'), (
        f"the edge served no quoted ETag to be conditional on: {etag!r}"
    )

    warm = _poll_until(lambda: session.get(url, timeout=15),
                       lambda r: r.headers.get("X-Cache") == "Hit from cloudfront",
                       timeout_s=120.0, interval_s=5.0,
                       description="the edge to hold a cached entry for the object")
    assert warm.headers.get("ETag") == etag, (
        f"the cached entry's ETag drifted from the one the viewer was given: "
        f"{warm.headers.get('ETag')!r} != {etag!r}"
    )

    # The effect: the object's own validator short-circuits the response to a bodiless 304.
    matched = session.get(url, headers={"If-None-Match": etag}, timeout=15)
    assert matched.status_code == 304, (
        f"a conditional GET presenting the object's own ETag {etag!r} was answered "
        f"{matched.status_code!r} instead of 304 / {matched.text[:200]!r}"
    )
    assert matched.content == b"", (
        f"the 304 carried a body, which a 304 may never do: {matched.content[:200]!r}"
    )
    assert matched.headers.get("ETag") == etag, (
        f"the 304 named a different entity than the one it was conditional on: "
        f"{matched.headers.get('ETag')!r} != {etag!r}"
    )

    # The effect is ABSENT for a validator the edge cannot be holding: exactly one thing changed,
    # the ETag presented, and the full body must come back.
    mismatched = session.get(url, headers={"If-None-Match": _WRONG_ETAG}, timeout=15)
    assert mismatched.status_code == 200, (
        f"a conditional GET presenting {_WRONG_ETAG!r} — an ETag no object can carry — was "
        f"answered {mismatched.status_code!r}; an edge that 304s a validator it does not hold "
        f"starves the viewer of content it never had"
    )
    assert mismatched.content == body, (
        f"the non-matching conditional GET returned 200 with {mismatched.content!r} instead of the "
        f"object's {body!r}"
    )
    assert mismatched.headers.get("ETag") == etag, (
        f"the 200 served for a non-matching validator named ETag "
        f"{mismatched.headers.get('ETag')!r}, not the object's {etag!r}"
    )

    # Positive control, unconditional and last: the cached entry survived both conditional requests.
    plain = session.get(url, timeout=15)
    assert plain.status_code == 200 and plain.content == body, (
        f"the unconditional control fetch returned {plain.status_code!r} / {plain.content!r} after "
        f"the conditional requests"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
