"""cfcache-range-beyond-object-rejected-and-partial-served-from-cache."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "cfcache-range-beyond-object-rejected-and-partial-served-from-cache"
GROUP = 'caching'
SERVICES = ['cloudfront']

#: Marks a failure caused by an edge data plane that serves no traffic at all.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: 2048 bytes covering every byte value eight times over. Deterministic, so the expected slice is
#: computable rather than remembered, and every 10-byte window is distinguishable from every other
#: one — a target that returns the WRONG range cannot pass by returning some plausible bytes.
_BLOB = bytes(range(256)) * 8

#: The requested window. Chosen away from both ends so an off-by-one or a whole-object answer is
#: visible in the bytes rather than only in the status line.
_FIRST, _LAST = 10, 19

#: TTLs that keep the whole check inside one cached entry: a partial served from the origin instead
#: of the cache would mean an expiry, not a range decision.
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

    Create -> Deployed and disable -> Deployed each take a few minutes; 900 s leaves wide margin.
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

@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A range beyond the cached object is refused 416 without the object's bytes, while a range
    inside it is the exact byte slice and an unconditional fetch still serves the whole object.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfrange-").lower()
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "range-beyond-object-rejected-and-partial-served-from-cache"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

    key = "blob.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=_BLOB,
                  ContentType="application/octet-stream")

    policy_id = cf.create_cache_policy(CachePolicyConfig={
        "Name": ctx.unique_name("sim2real-behav-cfrange-cp-"),
        "Comment": "sim2real range over a cached object",
        "MinTTL": _TTL, "DefaultTTL": _TTL, "MaxTTL": _TTL,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            # Compression off on purpose: a compressed response would make the byte arithmetic in
            # this check a statement about the compressor rather than about the range.
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
        "Name": ctx.unique_name("sim2real-behav-cfrange-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfrange-cr-"),
        "Comment": "sim2real range beyond object rejected",
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
    # so every range below is computed against the entry the first request established.
    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)
    url = f"{edge}/{key}"

    cold = _fetch(session, url)
    assert cold.content == _BLOB, (
        f"the cold fetch served {len(cold.content)} bytes that are not the origin object's "
        f"{len(_BLOB)}: {cold.content[:32]!r}"
    )
    warm = _poll_until(lambda: session.get(url, timeout=15),
                       lambda r: r.headers.get("X-Cache") == "Hit from cloudfront",
                       timeout_s=120.0, interval_s=5.0,
                       description="the edge to hold a cached entry for the whole object")
    assert warm.content == _BLOB, (
        f"the warm whole-object response diverged from the origin bytes: {warm.content[:32]!r}"
    )

    # The rejection: a window that starts past the end of the object cannot be satisfied from the
    # entry the edge holds, and the object's bytes must not leak out in its place.
    beyond_first = len(_BLOB) + 2048
    unsatisfiable = session.get(
        url, headers={"Range": f"bytes={beyond_first}-{beyond_first + 9}"}, timeout=15)
    assert unsatisfiable.status_code == 416, (
        f"a Range starting at byte {beyond_first} of a {len(_BLOB)}-byte object was answered "
        f"{unsatisfiable.status_code!r}; an edge that ignores an unsatisfiable Range and serves the "
        f"whole object is over-permissive: {unsatisfiable.content[:200]!r}"
    )
    assert _BLOB[:32] not in unsatisfiable.content, (
        f"the 416 response carries the object's own bytes: {unsatisfiable.content[:200]!r}"
    )

    # The effect: a satisfiable window is the exact slice of the object, described exactly.
    partial = session.get(url, headers={"Range": f"bytes={_FIRST}-{_LAST}"}, timeout=15)
    assert partial.status_code == 206, (
        f"a satisfiable Range over a cached object was answered {partial.status_code!r} instead of "
        f"206: {partial.content[:200]!r}"
    )
    assert partial.content == _BLOB[_FIRST:_LAST + 1], (
        f"the partial response carried {partial.content!r}, not bytes {_FIRST}-{_LAST} of the "
        f"object, which are {_BLOB[_FIRST:_LAST + 1]!r}"
    )
    assert partial.headers.get("Content-Range") == f"bytes {_FIRST}-{_LAST}/{len(_BLOB)}", (
        f"the partial response described itself as "
        f"{partial.headers.get('Content-Range')!r}, not "
        f"{f'bytes {_FIRST}-{_LAST}/{len(_BLOB)}'!r}"
    )
    assert partial.headers.get("Content-Length") == str(_LAST - _FIRST + 1), (
        f"the partial response declared Content-Length "
        f"{partial.headers.get('Content-Length')!r} for a {_LAST - _FIRST + 1}-byte window"
    )

    # Positive control, last: neither the refusal nor the partial disturbed the whole-object entry.
    whole = session.get(url, timeout=15)
    assert whole.status_code == 200 and whole.content == _BLOB, (
        f"the whole-object control fetch returned {whole.status_code!r} with "
        f"{len(whole.content)} bytes after the range requests"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
