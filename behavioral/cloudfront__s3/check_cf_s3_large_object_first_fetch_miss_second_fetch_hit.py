"""cf-s3-large-object-first-fetch-miss-second-fetch-hit."""
from __future__ import annotations

import json
import os
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cf-s3-large-object-first-fetch-miss-second-fetch-hit"
GROUP = "data-plane"
SERVICES = ["cloudfront", "s3"]

_CACHING_OPTIMIZED_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_OBJECT_SIZE_BYTES = 3 * 1024 * 1024


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {description}")
        time.sleep(interval_s)


def _empty_and_delete_bucket(s3, bucket):
    pages = s3.get_paginator("list_object_versions").paginate(Bucket=bucket)
    for page in pages:
        targets = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if targets:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
            if failed:
                raise AssertionError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]!r}")
    s3.delete_bucket(Bucket=bucket)


def _delete_oac(cf, oac_id):
    etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
    cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)


def _wait_deployed(cf, dist_id, *, timeout_s=900, interval_s=15):
    def probe():
        return cf.get_distribution(Id=dist_id)["Distribution"]["Status"]

    _poll(probe, lambda status: status == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
          description="the distribution reaching status Deployed")


def _delete_distribution(cf, dist_id):
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg["Enabled"]:
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
        _wait_deployed(cf, dist_id)
        etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A several-megabyte S3-origin object under the managed CachingOptimized cache policy answers
    the first viewer fetch from the origin (X-Cache: Miss) and the second from the edge
    (X-Cache: Hit), with the same exact body both times.
    """
    import requests

    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    bucket = ctx.unique_name("sim2real-behav-cfs3bkt-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    key = "large-object.bin"
    body = os.urandom(_OBJECT_SIZE_BYTES)
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="application/octet-stream")

    oac = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": ctx.unique_name("sim2real-behav-cfs3oac-"),
            "OriginAccessControlOriginType": "s3",
            "SigningBehavior": "always",
            "SigningProtocol": "sigv4",
        }
    )["OriginAccessControl"]
    oac_id = oac["Id"]
    ctx.on_cleanup(lambda: _delete_oac(cf, oac_id))

    origin_id = "s3-large-object-origin"
    bucket_domain = f"{bucket}.s3.{ctx.region}.amazonaws.com"
    dist_config = {
        "CallerReference": ctx.unique_name("sim2real-behav-cfs3-"),
        "Comment": "",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": bucket_domain,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                    "OriginAccessControlId": oac_id,
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _CACHING_OPTIMIZED_POLICY_ID,
        },
    }
    created = cf.create_distribution(DistributionConfig=dist_config)["Distribution"]
    dist_id = created["Id"]
    dist_arn = created["ARN"]
    domain_name = created["DomainName"]
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))

    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowCloudFrontServicePrincipalRead",
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

    _wait_deployed(cf, dist_id)

    url, route_headers = ctx.endpoint_route(f"{domain_name}/{key}")

    def fetch():
        try:
            return requests.get(url, headers=route_headers, timeout=30, verify=ctx.http_verify)
        except (requests.ConnectionError, requests.Timeout):
            return None

    first = _poll(
        fetch,
        lambda r: r is not None and r.status_code == 200 and r.headers.get("X-Cache") == "Miss from cloudfront",
        timeout_s=180,
        interval_s=10,
        description="a 200 response carrying X-Cache: Miss from cloudfront",
    )
    assert first.status_code == 200, f"expected 200 on the first fetch, got {first.status_code}"
    assert first.headers.get("X-Cache") == "Miss from cloudfront", (
        f"expected X-Cache 'Miss from cloudfront' on the first fetch, got {first.headers.get('X-Cache')!r}"
    )
    assert first.content == body, (
        f"first fetch body length {len(first.content)} != expected {len(body)}, or content differs"
    )

    second = _poll(
        fetch,
        lambda r: r is not None and r.status_code == 200 and r.headers.get("X-Cache") == "Hit from cloudfront",
        timeout_s=120,
        interval_s=10,
        description="a 200 response carrying X-Cache: Hit from cloudfront",
    )
    assert second.status_code == 200, f"expected 200 on the second fetch, got {second.status_code}"
    assert second.headers.get("X-Cache") == "Hit from cloudfront", (
        f"expected X-Cache 'Hit from cloudfront' on the second fetch, got {second.headers.get('X-Cache')!r}"
    )
    assert second.content == body, (
        f"second fetch body length {len(second.content)} != expected {len(body)}, or content differs"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
