"""cf-compression-serves-gzip-only-when-accept-encoding-present."""
from __future__ import annotations

import gzip
import json
import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cf-compression-serves-gzip-only-when-accept-encoding-present"
GROUP = 'policies'
SERVICES = ['cloudfront']

#: An endpoint data-plane FAIL marker.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: CloudFront compresses only objects between 1,000 and 10,000,000 bytes, and only for a documented
#: Content-Type allowlist that includes text/plain. 64 * 40 = 2560 bytes of highly repetitive text
#: satisfies both, and repetitive so the compressed form is unambiguously smaller.
_ORIGIN_BODY = (b"sim2real-cloudfront-compressible-payload-line\n" * 64)

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=900.0, interval_s=2.0) -> str:
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment.

    Create -> Deployed and disable -> Deployed each take a few minutes; 900s bounds both.
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
    ``DistributionNotDisabled``, so the second Deployed wait is mandatory rather than defensive.
    """
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_with_etag(get_fn, delete_fn, resource_id, *, timeout_s=120.0) -> None:
    """Delete by fresh ETag; retry the brief ...InUse a just-deleted distribution leaves behind."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("NoSuchCachePolicy", "NoSuchOriginAccessControl"):
                return
            if not code.endswith("InUse") or time.monotonic() > deadline:
                raise
        time.sleep(2)


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _raw_get(session, url, accept_encoding, *, timeout_s=180.0, interval_s=5.0):
    """GET with an explicit Accept-Encoding and return (response, UNDECODED body bytes).

    ``stream=True`` plus ``resp.raw.read()`` is what keeps the bytes compressed: requests
    transparently gunzips through ``resp.content``/``iter_content``, which would make a
    passthrough edge and a compressing edge indistinguishable — the exact thing under test.
    """
    last = None

    def probe():
        nonlocal last
        try:
            r = session.get(url, headers={"Accept-Encoding": accept_encoding},
                            stream=True, timeout=15)
            last = r
            return r
        except Exception as exc:  # noqa: BLE001 — transient during edge propagation; recorded
            last = exc
            return None

    try:
        resp = _poll_until(probe, lambda r: r is not None and r.status_code == 200,
                           timeout_s=timeout_s, interval_s=interval_s,
                           description=f"200 from {url} with Accept-Encoding: {accept_encoding}")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc
    return resp, resp.raw.read(decode_content=False)


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """The edge gzips a response only for a viewer that asked for gzip, and the bytes round-trip.

    Compression is work the edge performs after the origin answers; the gzip leg is read raw and
    gunzipped here, so the assertion is on real compressed bytes.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfgz-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS_KV})

    key = "payload.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=_ORIGIN_BODY, ContentType="text/plain")

    # EnableAcceptEncodingGzip=true is what puts a normalised Accept-Encoding into the cache key,
    # so the gzip and identity viewers get separate entries instead of one poisoning the other.
    policy_id = cf.create_cache_policy(CachePolicyConfig={
        "Name": ctx.unique_name("sim2real-behav-cfgz-cp-"),
        "Comment": "sim2real gzip compression",
        "MinTTL": 600, "DefaultTTL": 600, "MaxTTL": 600,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": True,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    })["CachePolicy"]["Id"]
    ctx.on_cleanup(
        lambda: _delete_with_etag(cf.get_cache_policy, cf.delete_cache_policy, policy_id))

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfgz-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(
        cf.get_origin_access_control, cf.delete_origin_access_control, oac_id))

    dist = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": {
            "CallerReference": ctx.unique_name("sim2real-behav-cfgz-cr-"),
            "Comment": "sim2real gzip compression",
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
                "Compress": True,
            },
        },
        "Tags": {"Items": _TAGS_KV},
    })["Distribution"]
    dist_id = dist["Id"]
    # LIFO: the distribution goes first, so the cache policy and OAC are no longer in use.
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
    url = f"{edge}/{key}"

    gz_resp, gz_raw = _raw_get(session, url, "gzip")
    id_resp, id_raw = _raw_get(session, url, "identity")

    assert gz_resp.headers.get("content-encoding") == "gzip", (
        f"the edge did not compress for a gzip viewer: content-encoding="
        f"{gz_resp.headers.get('content-encoding')!r}, headers={dict(gz_resp.headers)!r}"
    )
    assert gzip.decompress(gz_raw) == _ORIGIN_BODY, (
        f"the gunzipped body does not match the origin object: "
        f"{gzip.decompress(gz_raw)[:64]!r} vs {_ORIGIN_BODY[:64]!r}"
    )
    assert len(gz_raw) < len(_ORIGIN_BODY), (
        f"the compressed payload is not smaller than the origin object: "
        f"{len(gz_raw)!r} vs {len(_ORIGIN_BODY)!r} bytes"
    )
    assert "content-encoding" not in {k.lower() for k in id_resp.headers}, (
        f"an identity viewer received an encoded response: content-encoding="
        f"{id_resp.headers.get('content-encoding')!r}"
    )
    assert id_raw == _ORIGIN_BODY, (
        f"the identity viewer got the wrong bytes: {id_raw[:64]!r} vs {_ORIGIN_BODY[:64]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
