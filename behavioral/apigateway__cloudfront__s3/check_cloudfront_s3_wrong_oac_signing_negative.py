"""cloudfront-s3-wrong-oac-signing-negative."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from json import dumps
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "cloudfront-s3-wrong-oac-signing-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudfront", "s3"]

CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """A bucket policy whose SourceArn condition names a different distribution denies access."""
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    bucket = _create_bucket(ctx)
    key = "index.html"
    body = f"secret-{ctx.unique_name('')}".encode()
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain")

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
                "CachePolicyId": CACHING_DISABLED,
            },
        },
    )

    # Break exactly one thing: the bucket policy IS present and grants the
    # cloudfront.amazonaws.com service principal GetObject, but its SourceArn
    # condition names a *different* (bogus) distribution, not this one.
    wrong_dist_arn = dist_arn[: dist_arn.rfind("/") + 1] + "EDBOGUSDIST0000"
    assert wrong_dist_arn != dist_arn, "test setup bug: bogus distribution ARN accidentally matches the real one"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCloudFrontServicePrincipal",
                "Effect": "Allow",
                "Principal": {"Service": "cloudfront.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringEquals": {"AWS:SourceArn": wrong_dist_arn}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=dumps(policy))

    _wait_distribution_status(cf, dist_id, "Deployed")
    base, route = ctx.endpoint_route(domain_name)
    url = f"{base}/{key}"

    status, resp_body, _headers = _poll_http(url, lambda s, b, h: s == 403, timeout_s=180.0, headers=route, verify=ctx.http_verify)
    assert status == 403, f"expected 403 when the bucket policy's SourceArn names a different distribution, got {status}: {resp_body!r}"
    assert b"AccessDenied" in resp_body, f"expected AccessDenied in the deny response, got {resp_body!r}"
    assert resp_body != body, "object content leaked through CloudFront despite the SourceArn mismatch"

    # Positive control: fix the SourceArn condition to the real distribution ARN and
    # confirm the identical distribution eventually serves the object.
    policy["Statement"][0]["Condition"]["StringEquals"]["AWS:SourceArn"] = dist_arn
    s3.put_bucket_policy(Bucket=bucket, Policy=dumps(policy))

    status, resp_body, _headers = _poll_http(url, lambda s, b, h: s == 200, timeout_s=180.0, headers=route, verify=ctx.http_verify)
    assert status == 200, f"expected 200 once the SourceArn condition names the real distribution, got {status}: {resp_body!r}"
    assert resp_body == body, "content served via CloudFront did not match the S3 object after fixing SourceArn"


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cf-s3-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    # us-east-1 is CreateBucket's implicit default; passing it as an explicit
    # LocationConstraint is rejected with InvalidLocationConstraint.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
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
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]})
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


def _teardown_distribution(cf: Any, dist_id: str) -> None:
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    config, etag = cfg_resp["DistributionConfig"], cfg_resp["ETag"]
    if config.get("Enabled"):
        config["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=config)
        _wait_distribution_status(cf, dist_id, "Deployed")
    etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _http_get(url: str, headers: dict[str, str], verify=True) -> tuple[int, bytes, dict[str, str]]:
    req = urllib.request.Request(url, headers={"User-Agent": "sim2real-behavioral-check", **headers})
    try:
        with urllib.request.urlopen(req, timeout=30, context=_https_context(verify)) as resp:  # noqa: S310
            return resp.status, resp.read(), {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), {k.lower(): v for k, v in (exc.headers or {}).items()}


def _poll_http(
    url: str,
    predicate: Callable[[int, bytes, dict[str, str]], bool],
    timeout_s: float = 180.0,
    interval_s: float = 5.0,
    headers: dict[str, str] | None = None,
    verify=True,
) -> tuple[int, bytes, dict[str, str]]:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        try:
            status, body, got = _http_get(url, headers or {}, verify=verify)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last = (None, str(exc), {})
            time.sleep(interval_s)
            continue
        last = (status, body, got)
        if predicate(status, body, got):
            return status, body, got
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
