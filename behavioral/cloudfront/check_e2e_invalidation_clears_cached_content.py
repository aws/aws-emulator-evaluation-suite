"""e2e-invalidation-clears-cached-content."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "e2e-invalidation-clears-cached-content"
GROUP = "e2e"
SERVICES = ["cloudfront"]

_CACHING_OPTIMIZED_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_OBJECT_KEY = "invalidation-target.txt"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A distribution with an S3 origin serves the object, keeps serving the cached copy right after the
    object is overwritten, and serves the new content once a CreateInvalidation for its path reaches
    Completed."""
    bucket_name = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket_name, Key=_OBJECT_KEY, Body=b"version-1", ContentType="text/plain")

    oac_id = _create_oac(ctx)
    dist_id, dist_arn, domain_name = _create_distribution(ctx, bucket_name, oac_id)
    _set_bucket_policy(ctx, bucket_name, dist_arn)
    _wait_distribution_deployed(ctx, dist_id)

    edge, route = ctx.endpoint_route(domain_name)
    url = f"{edge}/{_OBJECT_KEY}"
    first = _fetch_with_retries(url, route, timeout_s=180.0, verify=ctx.http_verify)
    assert first == b"version-1", f"expected initial fetch to return version-1, got {first!r}"
    second = _fetch_with_retries(url, route, timeout_s=60.0, verify=ctx.http_verify)
    assert second == b"version-1", f"expected second fetch to still return version-1, got {second!r}"

    s3.put_object(Bucket=bucket_name, Key=_OBJECT_KEY, Body=b"version-2", ContentType="text/plain")
    # Cache invariant: immediately after overwriting the origin object, the CDN (default
    # TTL is far longer than this test) still serves the cached bytes.
    still_stale = _fetch_with_retries(url, route, timeout_s=30.0, verify=ctx.http_verify)
    assert still_stale == b"version-1", "expected CloudFront to still serve the cached object"

    cf = ctx.client("cloudfront")
    invalidation = cf.create_invalidation(
        DistributionId=dist_id,
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": [f"/{_OBJECT_KEY}"]},
            "CallerReference": ctx.unique_name("sim2real-behav-inv-"),
        },
    )
    invalidation_id = invalidation["Invalidation"]["Id"]

    def _invalidation_completed() -> bool:
        status = cf.get_invalidation(DistributionId=dist_id, Id=invalidation_id)["Invalidation"][
            "Status"
        ]
        return status == "Completed"

    assert _poll_until(_invalidation_completed, timeout_s=300.0, interval_s=10.0), (
        "invalidation never reached Completed"
    )

    def _serves_new_content() -> bool:
        return _fetch_with_retries(url, route, timeout_s=30.0, verify=ctx.http_verify) == b"version-2"

    assert _poll_until(_serves_new_content, timeout_s=180.0, interval_s=10.0), (
        "cache never stopped serving the stale object after invalidation completed"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-cfinv-")
    kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "fidelity", "Value": "sim2real-behav-cfinv"}]})
    return bucket_name


def _empty_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        keys = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _create_oac(ctx) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": ctx.unique_name("sim2real-behav-oac-"),
            "OriginAccessControlOriginType": "s3",
            "SigningBehavior": "always",
            "SigningProtocol": "sigv4",
        }
    )
    oac_id = resp["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac(ctx, oac_id))
    return oac_id


def _delete_oac(ctx, oac_id: str) -> None:
    cf = ctx.client("cloudfront")
    etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
    cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)


def _create_distribution(ctx, bucket_name: str, oac_id: str):
    cf = ctx.client("cloudfront")
    origin_domain = f"{bucket_name}.s3.{ctx.region}.amazonaws.com"
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-behav-dist-"),
            "Comment": "sim2real behavioral invalidation e2e check",
            "Enabled": True,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "s3origin",
                        "DomainName": origin_domain,
                        "S3OriginConfig": {"OriginAccessIdentity": ""},
                        "OriginAccessControlId": oac_id,
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "s3origin",
                "ViewerProtocolPolicy": "redirect-to-https",
                "CachePolicyId": _CACHING_OPTIMIZED_POLICY_ID,
            },
        }
    )
    dist = resp["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": [{"Key": "fidelity", "Value": "sim2real-behav-cfinv"}]})
    return dist_id, dist["ARN"], dist["DomainName"]


def _set_bucket_policy(ctx, bucket_name: str, dist_arn: str) -> None:
    s3 = ctx.client("s3")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCloudFrontServicePrincipal",
                "Effect": "Allow",
                "Principal": {"Service": "cloudfront.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))


def _wait_distribution_deployed(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    waiter = cf.get_waiter("distribution_deployed")
    waiter.wait(Id=dist_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900})
    status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
    assert status == "Deployed", f"expected Deployed, got {status}"


def _disable_and_delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    got = cf.get_distribution(Id=dist_id)
    config = got["Distribution"]["DistributionConfig"]
    if config.get("Enabled"):
        config["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=got["ETag"], DistributionConfig=config)
        _wait_distribution_deployed(ctx, dist_id)
    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _fetch_with_retries(url: str, route: dict, *, timeout_s: float, verify=True) -> bytes:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=route), timeout=15, context=_https_context(verify)) as resp:
                return resp.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_err = exc
            time.sleep(2)
    raise AssertionError(f"could not fetch {url} within {timeout_s}s: {last_err}")


def _poll_until(probe, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return probe()


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
