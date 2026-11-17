"""cache-tag-invalidation-of-an-unmatched-tag-evicts-nothing."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cache-tag-invalidation-of-an-unmatched-tag-evicts-nothing"
GROUP = "cache-tag-invalidation"
SERVICES = ["cloudfront", "s3"]

#: The header CacheTagConfig names; this matches S3's user-metadata echo for a "cache-tag" key.
_CACHE_TAG_HEADER = "x-amz-meta-cache-tag"
_TAG_A = "route:alpha"
_TAG_B = "route:beta"
#: A tag no object in this check ever carries.
_UNMATCHED_TAG = "route:never-used"
_KEY_A = "object-a.txt"
_KEY_B = "object-b.txt"
_V1 = "sim2real cache-tag payload v1"
_V2 = "sim2real cache-tag payload v2"


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A tag-scoped invalidation whose tag no cached object carries evicts neither object; a
    later invalidation of a tag one of them does carry then refreshes only that one.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx)
    oac_id = _new_origin_access_control(ctx)

    s3.put_object(Bucket=bucket, Key=_KEY_A, Body=_V1.encode("utf-8"),
                  ContentType="text/plain", Metadata={"cache-tag": _TAG_A})
    s3.put_object(Bucket=bucket, Key=_KEY_B, Body=_V1.encode("utf-8"),
                  ContentType="text/plain", Metadata={"cache-tag": _TAG_B})

    created = _new_distribution(ctx, bucket, oac_id)["Distribution"]
    did, domain = created["Id"], created["DomainName"]
    _grant_distribution(ctx, bucket, created["ARN"])
    _wait_deployed(cf, did)

    url_a = f"{domain}/{_KEY_A}"
    url_b = f"{domain}/{_KEY_B}"

    for label, url in (("A", url_a), ("B", url_b)):
        status, _, body = _get(ctx, url)
        assert (status, body) == (200, _V1), (
            f"first GET of object {label} returned ({status!r}, {body!r}), expected (200, {_V1!r})"
        )
        _, headers, body = _get_until(
            ctx, url, lambda st, h, b: st == 200 and b == _V1 and h.get("X-Cache", "").startswith("Hit"),
            f"object {label} re-served from the edge cache as a Hit",
        )
        assert body == _V1 and headers.get("X-Cache", "").startswith("Hit"), (
            f"a later GET of object {label} served body {body!r} with X-Cache "
            f"{headers.get('X-Cache')!r}; expected ({_V1!r}, a cache Hit)"
        )

    s3.put_object(Bucket=bucket, Key=_KEY_A, Body=_V2.encode("utf-8"),
                  ContentType="text/plain", Metadata={"cache-tag": _TAG_A})
    s3.put_object(Bucket=bucket, Key=_KEY_B, Body=_V2.encode("utf-8"),
                  ContentType="text/plain", Metadata={"cache-tag": _TAG_B})

    _invalidate(ctx, cf, did, _UNMATCHED_TAG)

    for label, url in (("A", url_a), ("B", url_b)):
        status, headers, body = _get(ctx, url)
        assert status == 200 and body == _V1 and headers.get("X-Cache", "").startswith("Hit"), (
            f"after invalidating the unmatched tag {_UNMATCHED_TAG!r}, object {label} returned "
            f"status {status!r}, body {body!r}, X-Cache {headers.get('X-Cache')!r}; expected "
            f"(200, {_V1!r}, still a cache Hit) since no object carries that tag"
        )

    _invalidate(ctx, cf, did, _TAG_A)

    _, headers, body = _get_until(
        ctx, url_a, lambda st, h, b: st == 200 and b == _V2 and h.get("X-Cache", "").startswith("Miss"),
        "object A served fresh after its own tag was invalidated",
    )
    assert body == _V2 and headers.get("X-Cache", "").startswith("Miss"), (
        f"after invalidating {_TAG_A!r}, object A served body {body!r} with X-Cache "
        f"{headers.get('X-Cache')!r}; expected ({_V2!r}, a cache Miss)"
    )

    status, headers, body = _get(ctx, url_b)
    assert status == 200 and body == _V1 and headers.get("X-Cache", "").startswith("Hit"), (
        f"after invalidating {_TAG_A!r}, object B returned status {status!r}, body {body!r}, "
        f"X-Cache {headers.get('X-Cache')!r}; expected (200, {_V1!r}, still a cache Hit) since it "
        f"carries a different tag"
    )


#: AWS's managed "CachingOptimized" cache policy -- an AWS-owned public id, not account state.
_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
#: Create/update, disable and delete each settle in minutes; the teardown polls to this deadline.
_DEPLOYED_DEADLINE_S = 900
_INVALIDATION_DEADLINE_S = 300


def _new_bucket(ctx) -> str:
    """A private bucket, all public access blocked, for the distribution's S3 origin."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cf-notag-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _drop_bucket(ctx, bucket))
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    })
    return bucket


def _new_origin_access_control(ctx) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-cf-notag-oac-"),
        "Description": CHECK,
        "SigningProtocol": "sigv4",
        "SigningBehavior": "always",
        "OriginAccessControlOriginType": "s3",
    })
    oac_id = resp["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _drop_origin_access_control(ctx, oac_id))
    return oac_id


def _new_distribution(ctx, bucket: str, oac_id: str) -> dict:
    """A deployed S3-origin distribution naming the cache-tag header; registers teardown."""
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-cf-notag-"),
        "Comment": CHECK,
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "notag-site",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "notag-site",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": _CACHING_OPTIMIZED,
        },
        "CacheTagConfig": {"HeaderName": _CACHE_TAG_HEADER},
    })
    did = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, did))
    return resp


def _grant_distribution(ctx, bucket: str, distribution_arn: str) -> None:
    """Let only this distribution's OAC read the bucket's objects."""
    s3 = ctx.client("s3")
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipalReadOnly",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"aws:SourceArn": distribution_arn}},
        }],
    })
    s3.put_bucket_policy(Bucket=bucket, Policy=policy)


def _invalidate(ctx, cf, did: str, tag: str) -> None:
    inv = cf.create_invalidation(DistributionId=did, InvalidationBatch={
        "Paths": {"Quantity": 1, "Items": [f"#{tag}"]},
        "CallerReference": ctx.unique_name("sim2real-inv-"),
    })["Invalidation"]
    _wait_invalidation_completed(cf, did, inv["Id"])


def _wait_deployed(cf, did: str) -> dict:
    deadline = time.monotonic() + _DEPLOYED_DEADLINE_S
    while True:
        got = cf.get_distribution(Id=did)
        if got["Distribution"]["Status"] == "Deployed":
            return got
        assert time.monotonic() < deadline, (
            f"distribution {did} did not reach Deployed within {_DEPLOYED_DEADLINE_S}s "
            f"(status {got['Distribution']['Status']!r})"
        )
        time.sleep(5)


def _wait_invalidation_completed(cf, did: str, iid: str) -> dict:
    deadline = time.monotonic() + _INVALIDATION_DEADLINE_S
    last = None
    while time.monotonic() < deadline:
        last = cf.get_invalidation(DistributionId=did, Id=iid)["Invalidation"]
        if last["Status"] == "Completed":
            return last
        time.sleep(5)
    raise AssertionError(f"invalidation {iid} did not complete within {_INVALIDATION_DEADLINE_S}s: {last!r}")


def _get(ctx, url: str) -> tuple[int | None, dict, str]:
    """One raw GET, no redirects followed. ``(None, {}, reason)`` when the host does not answer."""

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    try:
        target, route_headers = ctx.endpoint_route(url)
        opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPSHandler(context=_https_context(ctx.http_verify))
        )
        with opener.open(urllib.request.Request(target, headers=route_headers), timeout=20) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        return None, {}, f"{type(exc).__name__}: {exc}"


def _get_until(ctx, url: str, predicate, description: str, *, max_attempts: int = 10,
               interval_s: float = 6.0) -> tuple[int | None, dict, str]:
    """GET until ``predicate(status, headers, body)``; a freshly invalidated edge needs a moment."""
    last = None
    for _ in range(max_attempts):
        last = _get(ctx, url)
        if predicate(*last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {max_attempts} attempts; last {last!r}")


def _delete_distribution(ctx, did: str) -> None:
    """Disable if enabled, wait for Deployed, delete with the current ETag; raises if it survives."""
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + _DEPLOYED_DEADLINE_S
    while time.monotonic() < deadline:
        try:
            got = cf.get_distribution(Id=did)
            cfg = got["Distribution"]["DistributionConfig"]
            if cfg["Enabled"]:
                cfg["Enabled"] = False
                cf.update_distribution(Id=did, IfMatch=got["ETag"], DistributionConfig=cfg)
            elif got["Distribution"]["Status"] == "Deployed":
                cf.delete_distribution(Id=did, IfMatch=got["ETag"])
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchDistribution":
                return
            if code not in ("DistributionNotDisabled", "PreconditionFailed"):
                raise
        time.sleep(10)
    raise AssertionError(f"distribution {did} not deleted within {_DEPLOYED_DEADLINE_S}s")


def _drop_origin_access_control(ctx, oac_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
        cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchOriginAccessControl":
            raise


def _drop_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents") or []]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) and verify else None)
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
