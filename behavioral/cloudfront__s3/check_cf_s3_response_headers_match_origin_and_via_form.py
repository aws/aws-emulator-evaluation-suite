"""cf-s3-response-headers-match-origin-and-via-form."""
from __future__ import annotations

import datetime
import email.utils
import json
import re
import time

import requests

from behavioral_harness import tags

CHECK = "cf-s3-response-headers-match-origin-and-via-form"
GROUP = "data-plane"
SERVICES = ["cloudfront", "s3"]

#: Marks a failure caused by an edge data plane that serves no traffic at all.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

_VIA_RE = re.compile(r"^\d\.\d [0-9A-Za-z]+\.cloudfront\.net \(CloudFront\)$")


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
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
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


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A viewer GET through a CloudFront distribution over an OAC-locked S3 origin answers 200 with
    the object's own Content-Type, ETag, Last-Modified and Cache-Control, and a Via header of the
    documented form "http-version alphanumeric.cloudfront.net (CloudFront)".
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfhdr-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    key = "page/index.html"
    body = b"<!doctype html><title>sim2real-cf-headers</title>"
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/html",
                  CacheControl="max-age=60")
    head = s3.head_object(Bucket=bucket, Key=key)

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfhdr-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    origin_id = "s3origin"
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfhdr-cr-"),
        "Comment": "sim2real cf-s3-response-headers-match-origin-and-via-form",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": origin_id,
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_OPTIMIZED,
        },
    })["Distribution"]
    dist_id, domain = dist["Id"], dist["DomainName"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    dist_arn = dist["ARN"]
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [
        {"Key": "sim2real", "Value": "behavioral"},
    ]})

    _allow_cloudfront_oac(s3, bucket, dist_arn)
    _wait_distribution_deployed(cf, dist_id)

    url, route_headers = ctx.endpoint_route(f"{domain}/{key}")

    def fetch():
        try:
            return requests.get(url, headers=route_headers, timeout=15, verify=ctx.http_verify)
        except (requests.ConnectionError, requests.Timeout):
            return None

    try:
        resp = _poll_until(
            fetch,
            lambda r: r is not None and r.status_code == 200,
            timeout_s=180, interval_s=10,
            description=f"200 fetching {url}",
        )
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc

    assert resp.status_code == 200, f"expected 200 fetching {url}, got {resp.status_code}"
    assert resp.content == body, f"unexpected body: {resp.content!r}"

    assert resp.headers.get("Content-Type") == head["ContentType"], (
        f"viewer Content-Type {resp.headers.get('Content-Type')!r} does not match the object's "
        f"own {head['ContentType']!r}"
    )
    assert resp.headers.get("ETag") == head["ETag"], (
        f"viewer ETag {resp.headers.get('ETag')!r} does not match the object's own {head['ETag']!r}"
    )
    last_modified_utc = head["LastModified"].astimezone(datetime.timezone.utc)
    expected_last_modified = email.utils.format_datetime(last_modified_utc, usegmt=True)
    assert resp.headers.get("Last-Modified") == expected_last_modified, (
        f"viewer Last-Modified {resp.headers.get('Last-Modified')!r} does not match the object's "
        f"own {expected_last_modified!r}"
    )
    assert resp.headers.get("Cache-Control") == head["CacheControl"], (
        f"viewer Cache-Control {resp.headers.get('Cache-Control')!r} does not match the object's "
        f"own {head['CacheControl']!r}"
    )

    via = resp.headers.get("Via")
    assert via is not None and _VIA_RE.match(via), (
        f"Via header {via!r} does not match the documented form "
        f"'http-version alphanumeric.cloudfront.net (CloudFront)'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
