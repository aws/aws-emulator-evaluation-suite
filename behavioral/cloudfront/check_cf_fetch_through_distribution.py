"""cf-fetch-through-distribution."""
from __future__ import annotations

import json
import time
import itertools

from behavioral_harness import tags
from botocore.exceptions import ClientError

_COUNTER = itertools.count()

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")

def _force_delete(get_fn, delete_fn, resource_id):
    """ETag-guarded delete of a CloudFront policy-like resource."""
    resp = get_fn(Id=resource_id)
    delete_fn(Id=resource_id, IfMatch=resp["ETag"])

def _wait_distribution_deployed(cf, dist_id, timeout_s=1200, interval_s=15, etag_hint=None):
    """Poll GetDistribution until Status == 'Deployed'; return the latest ETag."""
    holder = {"etag": etag_hint}
    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]
    _poll_until(probe, lambda status: status == "Deployed", timeout_s=timeout_s, interval_s=interval_s)
    return holder["etag"]

def _force_delete_distribution(cf, dist_id):
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id, etag_hint=etag)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)

def _empty_and_delete_bucket(s3, bucket):
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except Exception:
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
                keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if keys:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
    s3.delete_bucket(Bucket=bucket)

def _caller_reference(ctx, prefix="cf"):
    return ctx.unique_name(f"sim2real-behav-{prefix}-") + f"-{next(_COUNTER)}"

CHECK = "cf-fetch-through-distribution"
GROUP = 'data-plane'
SERVICES = ['cloudfront']

# Marks a failure caused by an edge data plane that serves no traffic at all.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A deployed distribution serves an OAC-locked S3-origin object over HTTP with status 200 and its
    exact body, and a second fetch is an edge cache Hit (``x-cache``).
    """
    cf = ctx.client("cloudfront")

    import requests

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-bkt-")
    # The bucket lives in the run's region; only us-east-1 takes no LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]},
    )

    key = "index.html"
    body = b"sim2real-cloudfront-origin-object"
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/html")

    oac = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": ctx.unique_name("sim2real-behav-oac-"),
            "OriginAccessControlOriginType": "s3",
            "SigningBehavior": "always",
            "SigningProtocol": "sigv4",
        }
    )["OriginAccessControl"]
    oac_id = oac["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_origin_access_control, cf.delete_origin_access_control, oac_id))

    bucket_domain = f"{bucket}.s3.{ctx.region}.amazonaws.com"
    cfg = {
        "CallerReference": _caller_reference(ctx),
        "Comment": "sim2real cf-fetch-through",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "s3-origin",
                    "DomainName": bucket_domain,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                    "OriginAccessControlId": oac_id,
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3-origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_OPTIMIZED,
        },
    }
    resp = cf.create_distribution(DistributionConfig=cfg)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    # Registered last so it runs FIRST under ctx.on_cleanup's LIFO order: emptying and
    # deleting the bucket is fast, while disabling+redeploying the distribution before
    # delete routinely nears the 60s cleanup budget, so the bucket must not be queued
    # behind it.
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))
    domain = resp["Distribution"]["DomainName"]
    dist_arn = resp["Distribution"]["ARN"]
    cf.tag_resource(
        Resource=dist_arn,
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]},
    )

    # Lock the bucket to this distribution (OAC-signed CloudFront reads only).
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2008-10-17",
                "Statement": [
                    {
                        "Sid": "AllowCloudFrontServicePrincipal",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudfront.amazonaws.com"},
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                        "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
                    }
                ],
            }
        ),
    )

    _wait_distribution_deployed(cf, dist_id)

    url, route_headers = ctx.endpoint_route(f"{domain}/{key}")

    # First fetch: the edge may briefly 403/404 immediately post-deploy while
    # config propagates, so poll for a 200.
    last_exc: list[Exception] = []

    def fetch():
        try:
            return requests.get(url, headers=route_headers, timeout=15, verify=ctx.http_verify)
        except (requests.ConnectionError, requests.Timeout) as exc:
            # A transient connection error during propagation; kept so a timeout names its cause.
            last_exc.append(exc)
            return None

    # Marked as a data-plane failure: the distribution is Deployed and the domain is the target's
    # own, so 180 s without the object is the target's failure, not a transport problem.
    try:
        first = _poll_until(
            fetch,
            lambda r: r is not None and r.status_code == 200,
            timeout_s=180,
            interval_s=10,
            description="200 fetching object through the distribution",
        )
    except AssertionError as exc:
        tail = (
            f" (last transport error: {type(last_exc[-1]).__name__}: {last_exc[-1]})"
            if last_exc
            else ""
        )
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}{tail}") from exc
    assert first.status_code == 200, f"expected 200 fetching {url}, got {first.status_code}"
    assert first.content == body, f"unexpected body: {first.content!r}"

    # Second fetch: CloudFront should now serve from cache (x-cache: Hit).
    def cache_status():
        r = fetch()
        return r.headers.get("X-Cache", "") if r is not None else ""

    xcache = _poll_until(
        cache_status,
        lambda xc: "Hit" in xc,
        timeout_s=120,
        interval_s=10,
        description="CloudFront cache HIT on a repeat fetch",
    )
    assert "Hit" in xcache, f"expected a cache Hit, got X-Cache={xcache!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
