"""cloudfront-invalidation-s3-object-update-positive."""
from __future__ import annotations

import http.client
import ssl
import time
import urllib.error
import urllib.request
from json import dumps
from typing import Any, Callable
from urllib.parse import urlsplit

from behavioral_harness import tags

CHECK = "cloudfront-invalidation-s3-object-update-positive"
GROUP = "cache-invalidation"
SERVICES = ["apigateway", "cloudfront", "s3"]

# Managed CachingOptimized policy: Default TTL 86400s, so a second request made
# seconds after the first is guaranteed to still be served from cache.
CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """Updating the S3 object and issuing an invalidation makes CloudFront re-fetch it."""
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    bucket = _create_bucket(ctx)
    key = "object.txt"
    body_v1 = f"v1-{ctx.unique_name('')}".encode()
    s3.put_object(Bucket=bucket, Key=key, Body=body_v1, ContentType="text/plain")

    oac_id = _create_oac(ctx)
    dist_id, dist_arn, domain_name = _create_distribution(
        ctx,
        {
            "CallerReference": ctx.unique_name("sim2real-cf-"),
            "Comment": "",
            "Enabled": True,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "s3-origin",
                        "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
                        "S3OriginConfig": {"OriginAccessIdentity": ""},
                        "OriginAccessControlId": oac_id,
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "s3-origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": CACHING_OPTIMIZED,
            },
        },
    )

    policy = {
        "Version": "2012-10-17",
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
    s3.put_bucket_policy(Bucket=bucket, Policy=dumps(policy))

    _wait_distribution_status(cf, dist_id, "Deployed")
    url, route_headers = ctx.endpoint_route(f"{domain_name}/{key}")

    # Use a single persistent HTTPS connection so every request in this cache check
    # lands on the same edge location -- CloudFront's anycast routing does not
    # guarantee two independent connections hit the same PoP, which would make a
    # cache assertion flaky for reasons unrelated to the behavior under test.
    parts = urlsplit(url)
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(
            parts.hostname, parts.port, timeout=30, context=_https_context(ctx.http_verify)
        )
    else:
        conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=30)
    ctx.on_cleanup(conn.close)

    # First request over the connection may be a cache miss (fetches from origin and
    # populates the edge). Poll on the *same* connection until the edge reports a
    # cache Hit, proving population has actually completed before we mutate the
    # origin object -- otherwise a same-timestamp miss on the next request would be
    # indistinguishable from "caching doesn't work" when it is really just "the
    # write to cache hadn't finished yet".
    def _is_hit(s: int, b: bytes, h: dict[str, str]) -> bool:
        return s == 200 and "hit from cloudfront" in h.get("x-cache", "").lower()

    status, resp_body, headers = _poll_http_conn(
        conn, parts.path, _is_hit, timeout_s=120.0, interval_s=3.0, route_headers=route_headers
    )
    assert status == 200, f"expected 200 from initial GET of {parts.path}, got {status}"
    assert resp_body == body_v1, f"expected initial GET body {body_v1!r}, got {resp_body!r}"
    assert "hit from cloudfront" in headers.get("x-cache", "").lower(), (
        f"expected x-cache to report a Hit once populated, got {headers.get('x-cache')!r}"
    )

    # Update the object in S3 without invalidating: CloudFront must keep serving the
    # cached v1 bytes for the (86400s default TTL) cache policy's lifetime.
    body_v2 = f"v2-{ctx.unique_name('')}".encode()
    s3.put_object(Bucket=bucket, Key=key, Body=body_v2, ContentType="text/plain")
    status, resp_body, headers = _get_via_conn(conn, parts.path, route_headers)
    assert status == 200, f"expected 200 from post-update GET of {parts.path}, got {status}"
    assert resp_body == body_v1, (
        f"expected stale cached v1 body {body_v1!r} before invalidation, got {resp_body!r}"
    )
    assert "hit from cloudfront" in headers.get("x-cache", "").lower(), (
        f"expected post-update GET to still be an edge cache Hit, got {headers.get('x-cache')!r}"
    )
    conn.close()


    # Now invalidate the path and wait for the invalidation to complete.
    inv = cf.create_invalidation(
        DistributionId=dist_id,
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": [f"/{key}"]},
            "CallerReference": ctx.unique_name("sim2real-inv-"),
        },
    )
    inv_id = inv["Invalidation"]["Id"]
    _wait_invalidation_completed(cf, dist_id, inv_id)

    # After invalidation completes, the next fetch must be re-fetched from origin -> v2.
    status, resp_body, _headers = _poll_http(
        url, lambda s, b, h: s == 200 and b == body_v2, timeout_s=180.0, route_headers=route_headers, verify=ctx.http_verify
    )
    assert status == 200, f"expected 200 from post-invalidation GET of {url}, got {status}"
    assert resp_body == body_v2, f"expected refreshed body {body_v2!r} after invalidation, got {resp_body!r}"


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cf-s3-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    # us-east-1 is CreateBucket's own default region and is the one region where the API
    # rejects an explicit LocationConstraint -- not a pinned resource, an S3 API quirk.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(s3: Any, bucket: str) -> None:
    resp = s3.list_objects_v2(Bucket=bucket)
    objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
    if objs:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_oac(ctx: Any) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": ctx.unique_name("sim2real-oac-"),
            "Description": "sim2real behavioral check",
            "SigningProtocol": "sigv4",
            "SigningBehavior": "always",
            "OriginAccessControlOriginType": "s3",
        }
    )
    oac_id = resp["OriginAccessControl"]["Id"]

    def _cleanup() -> None:
        etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
        cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)

    ctx.on_cleanup(_cleanup)
    return oac_id


def _create_distribution(ctx: Any, config: dict[str, Any]) -> tuple[str, str, str]:
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution(DistributionConfig=config)
    dist = resp["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _teardown_distribution(cf, dist_id))
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]})
    return dist_id, dist["ARN"], dist["DomainName"]


def _wait_distribution_status(
    cf: Any, dist_id: str, status: str, timeout_s: float = 1500.0, interval_s: float = 15.0
) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if last == status:
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached status={status!r} (last={last!r})")


def _wait_invalidation_completed(
    cf: Any, dist_id: str, inv_id: str, timeout_s: float = 900.0, interval_s: float = 10.0
) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.get_invalidation(DistributionId=dist_id, Id=inv_id)["Invalidation"]["Status"]
        if last == "Completed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"invalidation {inv_id} never completed (last status={last!r})")


def _teardown_distribution(cf: Any, dist_id: str) -> None:
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    config, etag = cfg_resp["DistributionConfig"], cfg_resp["ETag"]
    if config.get("Enabled"):
        config["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=config)
        _wait_distribution_status(cf, dist_id, "Deployed")
    etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _http_get(url: str, route_headers: dict[str, str] | None = None, verify=True) -> tuple[int, bytes, dict[str, str]]:
    req = urllib.request.Request(url, headers={"User-Agent": "sim2real-behavioral-check", **(route_headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=30, context=_https_context(verify)) as resp:  # noqa: S310
            return resp.status, resp.read(), {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), {k.lower(): v for k, v in (exc.headers or {}).items()}


def _get_via_conn(
    conn: http.client.HTTPSConnection, path: str, route_headers: dict[str, str] | None = None
) -> tuple[int, bytes, dict[str, str]]:
    conn.request("GET", path, headers={"User-Agent": "sim2real-behavioral-check", **(route_headers or {})})
    resp = conn.getresponse()
    body = resp.read()
    headers = {k.lower(): v for k, v in resp.getheaders()}
    return resp.status, body, headers


def _poll_http_conn(
    conn: http.client.HTTPSConnection,
    path: str,
    predicate: Callable[[int, bytes, dict[str, str]], bool],
    timeout_s: float = 180.0,
    interval_s: float = 5.0,
    route_headers: dict[str, str] | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        try:
            status, body, headers = _get_via_conn(conn, path, route_headers)
        except (http.client.HTTPException, OSError) as exc:
            last = (None, str(exc), {})
            conn.close()
            conn.connect()
            time.sleep(interval_s)
            continue
        last = (status, body, headers)
        if predicate(status, body, headers):
            return status, body, headers
        time.sleep(interval_s)
    raise AssertionError(f"polling {path} never satisfied predicate; last={last}")



def _poll_http(
    url: str,
    predicate: Callable[[int, bytes, dict[str, str]], bool],
    timeout_s: float = 180.0,
    interval_s: float = 5.0,
    route_headers: dict[str, str] | None = None,
    verify=True,
) -> tuple[int, bytes, dict[str, str]]:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        try:
            status, body, headers = _http_get(url, route_headers, verify=verify)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last = (None, str(exc), {})
            time.sleep(interval_s)
            continue
        last = (status, body, headers)
        if predicate(status, body, headers):
            return status, body, headers
        time.sleep(interval_s)
    raise AssertionError(f"polling {url} never satisfied predicate; last={last}")


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
