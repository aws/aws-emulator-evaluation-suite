"""e2e-invalidation-clears-cached-object."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "e2e-invalidation-clears-cached-object"
GROUP = "e2e"
SERVICES = ["cloudfront"]

#: Every wait here (deploy, invalidation, edge convergence) is sized from the CloudFront (long)
#: service-class budget; it bounds the poll and is not an assertion on elapsed time.
_LONG_BUDGET_S = 1700


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An edge-cached object stays stale after the origin changes (5-minute MinTTL), an invalidation
    makes the next fetch return the update, and after delete plus invalidation the edge refuses it.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    oac_id = _create_oac(ctx)
    cache_policy_id = _create_cache_policy(ctx)
    dist_id, domain_name = _create_s3_distribution(ctx, bucket, oac_id, cache_policy_id)
    ctx.on_cleanup(lambda: _delete_oac(ctx, oac_id))
    ctx.on_cleanup(lambda: _delete_cache_policy(ctx, cache_policy_id))
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))

    _attach_bucket_policy(ctx, bucket, dist_id)
    s3.put_object(Bucket=bucket, Key="index.txt", Body=b"version-1", ContentType="text/plain")
    _wait_distribution_deployed(cf, dist_id)

    edge, route = ctx.endpoint_route(domain_name)
    url = f"{edge}/index.txt"
    tls = _tls(ctx)
    body1 = _poll_http_get(url, route, tls, timeout_s=_LONG_BUDGET_S)
    assert body1 == "version-1", f"expected initial fetch to return version-1, got {body1!r}"

    # Wait for a real cache Hit before relying on TTL semantics; the first request was the cold Miss.
    body_hit, xcache_hit = _poll_until_header(url, route, tls, "X-Cache", "Hit from cloudfront", timeout_s=_LONG_BUDGET_S, interval_s=3)
    assert body_hit == "version-1", f"expected cache Hit response to still be version-1, got {body_hit!r}"
    assert xcache_hit == "Hit from cloudfront", f"expected X-Cache: Hit from cloudfront, got {xcache_hit!r}"

    s3.put_object(Bucket=bucket, Key="index.txt", Body=b"version-2", ContentType="text/plain")

    # A single immediate check, not a poll: the 300 s MinTTL guarantees the stale copy is served.
    with urllib.request.urlopen(urllib.request.Request(url, headers=route), timeout=10, context=tls) as resp:
        stale_text = resp.read().decode("utf-8")
    assert stale_text == "version-1", f"expected stale cached content within MinTTL window, got {stale_text!r}"

    invalidation = cf.create_invalidation(
        DistributionId=dist_id,
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": ["/index.txt"]},
            "CallerReference": ctx.unique_name("sim2real-cf-inv-"),
        },
    )["Invalidation"]
    _wait_invalidation_completed(cf, dist_id, invalidation["Id"])

    body2 = _poll_http_get(url, route, tls, timeout_s=_LONG_BUDGET_S, expected_body="version-2")
    assert body2 == "version-2", f"expected fresh content after invalidation, got {body2!r}"

    # After delete plus invalidation, S3 through OAC answers AccessDenied/NoSuchKey (403/404).
    s3.delete_object(Bucket=bucket, Key="index.txt")
    gone_inv = cf.create_invalidation(
        DistributionId=dist_id,
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": ["/index.txt"]},
            "CallerReference": ctx.unique_name("sim2real-cf-inv-"),
        },
    )["Invalidation"]
    _wait_invalidation_completed(cf, dist_id, gone_inv["Id"])
    status, text = _poll_http_status(url, route, tls, lambda st, _t: st in (403, 404), timeout_s=_LONG_BUDGET_S)
    assert status in (403, 404), f"expected 403 or 404 for the deleted object at the edge, got {status}"
    assert "version-1" not in text and "version-2" not in text, (
        f"the edge still served a deleted object's content after invalidation: {text[:200]!r}"
    )


def _tls(ctx):
    """The TLS context ctx.http_verify asks for: a CA bundle path, unverified, or the default."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _tolerate(fn, code: str) -> None:
    """Teardown step: only the resource's own not-found code is tolerated; any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != code:
            raise


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cf-inval-").lower()
    # us-east-1 is S3's region-pinned default: CreateBucket there takes no LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    return bucket


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    _tolerate(lambda: _empty_and_delete_bucket(s3, bucket), "NoSuchBucket")


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_oac(ctx) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": ctx.unique_name("sim2real-cf-inval-oac-"),
            "OriginAccessControlOriginType": "s3",
            "SigningBehavior": "always",
            "SigningProtocol": "sigv4",
        }
    )
    return resp["OriginAccessControl"]["Id"]


def _delete_oac(ctx, oac_id: str) -> None:
    cf = ctx.client("cloudfront")

    def _delete() -> None:
        etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
        cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)

    _tolerate(_delete, "NoSuchOriginAccessControl")


def _create_cache_policy(ctx) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_cache_policy(
        CachePolicyConfig={
            "Name": ctx.unique_name("sim2real-cf-inval-cp-"),
            "DefaultTTL": 300,
            "MaxTTL": 300,
            "MinTTL": 300,
            "ParametersInCacheKeyAndForwardedToOrigin": {
                "CookiesConfig": {"CookieBehavior": "none"},
                "HeadersConfig": {"HeaderBehavior": "none"},
                "QueryStringsConfig": {"QueryStringBehavior": "none"},
                "EnableAcceptEncodingGzip": False,
                "EnableAcceptEncodingBrotli": False,
            },
        }
    )
    return resp["CachePolicy"]["Id"]


def _delete_cache_policy(ctx, cache_policy_id: str) -> None:
    cf = ctx.client("cloudfront")

    def _delete() -> None:
        etag = cf.get_cache_policy(Id=cache_policy_id)["ETag"]
        cf.delete_cache_policy(Id=cache_policy_id, IfMatch=etag)

    _tolerate(_delete, "NoSuchCachePolicy")


def _create_s3_distribution(ctx, bucket: str, oac_id: str, cache_policy_id: str) -> tuple[str, str]:
    cf = ctx.client("cloudfront")
    regional_domain = f"{bucket}.s3.{ctx.region}.amazonaws.com"
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-cf-inval-cr-"),
            "Comment": "sim2real behavioral: invalidation clears stale cache",
            "Enabled": True,
            "DefaultRootObject": "index.txt",
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "s3origin",
                        "DomainName": regional_domain,
                        "S3OriginConfig": {"OriginAccessIdentity": ""},
                        "OriginAccessControlId": oac_id,
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "s3origin",
                "ViewerProtocolPolicy": "redirect-to-https",
                "CachePolicyId": cache_policy_id,
            },
        }
    )
    dist = resp["Distribution"]
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]})
    return dist["Id"], dist["DomainName"]


def _attach_bucket_policy(ctx, bucket: str, dist_id: str) -> None:
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")
    dist_arn = cf.get_distribution(Id=dist_id)["Distribution"]["ARN"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudfront.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _wait_distribution_deployed(cf, dist_id: str, timeout_s: float = _LONG_BUDGET_S, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if cf.get_distribution(Id=dist_id)["Distribution"]["Status"] == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _wait_invalidation_completed(cf, dist_id: str, invalidation_id: str, timeout_s: float = _LONG_BUDGET_S, interval_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cf.get_invalidation(DistributionId=dist_id, Id=invalidation_id)["Invalidation"]["Status"]
        if status == "Completed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"invalidation {invalidation_id} never reached Completed within {timeout_s}s")


def _delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    _tolerate(lambda: _disable_and_delete_distribution(cf, dist_id), "NoSuchDistribution")


def _disable_and_delete_distribution(cf, dist_id: str) -> None:
    config_resp = cf.get_distribution_config(Id=dist_id)
    config = config_resp["DistributionConfig"]
    etag = config_resp["ETag"]
    if config.get("Enabled"):
        config["Enabled"] = False
        cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)
        _wait_distribution_deployed(cf, dist_id)
        etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _poll_http_get(url: str, route: dict, tls, timeout_s: float = 180.0, interval_s: float = 5.0, expected_body: str | None = None) -> str:
    deadline = time.monotonic() + timeout_s
    last_err: Any = None
    answered = False
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=route), timeout=10, context=tls) as resp:
                answered = True
                if resp.status == 200:
                    text = resp.read().decode("utf-8")
                    if expected_body is None or text == expected_body:
                        return text
                    last_err = AssertionError(f"body still {text!r}")
                else:
                    last_err = AssertionError(f"HTTP {resp.status}")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            answered = answered or isinstance(exc, urllib.error.HTTPError)
            last_err = exc
        time.sleep(interval_s)
    if not answered:
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: nothing answered at the distribution edge {url} within "
            f"{timeout_s}s (last: {last_err}), so no edge served the origin at all"
        )
    raise AssertionError(f"polling {url} never satisfied condition within {timeout_s}s (last: {last_err})")


def _poll_http_status(url: str, route: dict, tls, predicate, timeout_s: float, interval_s: float = 5.0) -> tuple[int | None, str]:
    """GET url until predicate(status, body) holds; 4xx answers are results, not errors."""
    deadline = time.monotonic() + timeout_s
    status, text, last_err = None, "", None
    while True:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=route), timeout=10, context=tls) as resp:
                status, text = resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            status, text = exc.code, exc.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError) as exc:
            last_err = exc
        if status is not None and predicate(status, text):
            return status, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"polling {url} never satisfied condition within {timeout_s}s "
                f"(last status {status}, body {text[:200]!r}, error {last_err})"
            )
        time.sleep(interval_s)


def _poll_until_header(
    url: str, route: dict, tls, header: str, expected_value: str, timeout_s: float = 180.0, interval_s: float = 5.0
) -> tuple[str, str]:
    deadline = time.monotonic() + timeout_s
    last_body, last_val, last_err = "", "", None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=route), timeout=10, context=tls) as resp:
                if resp.status == 200:
                    last_body = resp.read().decode("utf-8")
                    last_val = resp.headers.get(header, "")
                    if last_val == expected_value:
                        return last_body, last_val
                else:
                    last_err = AssertionError(f"HTTP {resp.status}")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_err = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"never observed {header}={expected_value!r} from {url} within {timeout_s}s "
        f"(last {header}={last_val!r}, last error: {last_err})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
