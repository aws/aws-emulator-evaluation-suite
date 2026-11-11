"""server-side-security-headers-policy-enforced-on-response."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "server-side-security-headers-policy-enforced-on-response"
GROUP = "server-side"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A response fetched through a distribution whose cache behavior carries a security-headers policy has
    X-Content-Type-Options nosniff, X-Frame-Options DENY and Strict-Transport-Security max-age=31536000.
    The origin is a private S3 bucket read through an origin access control."""
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-rhp-origin-")
    _create_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key="get", Body=b"sim2real-security-headers-origin")
    oac_id = _create_oac(ctx, cf)

    policy_id, _policy_etag = _create_security_headers_policy(ctx, cf)

    dist_id, domain, dist_arn = _create_distribution_with_response_headers_policy(
        ctx, cf, policy_id, f"{bucket}.s3.{ctx.region}.amazonaws.com", oac_id
    )
    _allow_distribution_to_read(s3, bucket, dist_arn)
    _wait_for_deployed(cf, dist_id)

    edge, route = ctx.endpoint_route(domain)
    body, headers = _fetch(f"{edge}/get", headers=route, verify=ctx.http_verify)
    assert headers.get("x-content-type-options") == "nosniff", (
        f"missing/incorrect X-Content-Type-Options header, got headers={dict(headers)}"
    )
    assert headers.get("x-frame-options") == "DENY", (
        f"missing/incorrect X-Frame-Options header, got headers={dict(headers)}"
    )
    assert "strict-transport-security" in headers and "max-age=31536000" in headers[
        "strict-transport-security"
    ], f"missing/incorrect Strict-Transport-Security header, got headers={dict(headers)}"


def _create_security_headers_policy(ctx, cf):
    name = ctx.unique_name("sim2real-rhp-")
    resp = cf.create_response_headers_policy(
        ResponseHeadersPolicyConfig={
            "Name": name,
            "Comment": "sim2real behavioral check",
            "SecurityHeadersConfig": {
                "ContentTypeOptions": {"Override": True},
                "FrameOptions": {"FrameOption": "DENY", "Override": True},
                "StrictTransportSecurity": {
                    "AccessControlMaxAgeSec": 31536000,
                    "IncludeSubdomains": False,
                    "Override": True,
                    "Preload": False,
                },
            },
        }
    )
    policy_id = resp["ResponseHeadersPolicy"]["Id"]
    etag = resp["ETag"]
    ctx.on_cleanup(lambda: _delete_response_headers_policy(ctx, cf, policy_id))
    return policy_id, etag


def _delete_response_headers_policy(ctx, cf, policy_id: str) -> None:
    etag = cf.get_response_headers_policy(Id=policy_id)["ETag"]
    cf.delete_response_headers_policy(Id=policy_id, IfMatch=etag)


def _create_bucket(ctx, s3, bucket: str) -> None:
    """A private bucket: Block Public Access stays at its default (all four settings on)."""
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_oac(ctx, cf) -> str:
    resp = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": ctx.unique_name("sim2real-rhp-oac-"),
            "Description": "sim2real behavioral check",
            "OriginAccessControlOriginType": "s3",
            "SigningBehavior": "always",
            "SigningProtocol": "sigv4",
        }
    )
    oac_id = resp["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac(cf, oac_id))
    return oac_id


def _delete_oac(cf, oac_id: str) -> None:
    etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
    cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)


def _allow_distribution_to_read(s3, bucket: str, dist_arn: str) -> None:
    """s3:GetObject for the CloudFront service principal, only on behalf of this distribution."""
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


def _create_distribution_with_response_headers_policy(ctx, cf, policy_id: str, origin_domain: str, oac_id: str):
    origin_id = ctx.unique_name("sim2real-origin-")
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-dist-"),
            "Comment": "sim2real behavioral check",
            "Enabled": True,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": origin_id,
                        "DomainName": origin_domain,
                        "OriginAccessControlId": oac_id,
                        "S3OriginConfig": {"OriginAccessIdentity": ""},
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": origin_id,
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
                "ResponseHeadersPolicyId": policy_id,
            },
        }
    )
    dist_id = resp["Distribution"]["Id"]
    domain = resp["Distribution"]["DomainName"]
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))
    return dist_id, domain, resp["Distribution"]["ARN"]


def _wait_for_deployed(cf, dist_id: str, timeout_s: float = 1800.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if cf.get_distribution(Id=dist_id)["Distribution"]["Status"] == "Deployed":
            return
        time.sleep(2)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _delete_distribution(cf, dist_id: str) -> None:
    cur = cf.get_distribution_config(Id=dist_id)
    cfg, etag = cur["DistributionConfig"], cur["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    # budget.cleanup_timeout for behavioral/cloudfront is 1800 s; the OAC and bucket teardowns run after this one.
    deadline = time.monotonic() + 1800 - 120
    while time.monotonic() < deadline:
        dist = cf.get_distribution(Id=dist_id)
        if dist["Distribution"]["Status"] == "Deployed":
            etag = dist["ETag"]
            break
        time.sleep(15)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _fetch(url: str, data: bytes | None = None, headers: dict | None = None, timeout_s: float = 600.0, verify=True):
    """GET (or POST if data given) through the distribution, retrying while
    CloudFront/edge propagation settles just after deployment."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(url, data=data, headers=headers or {})
            with urllib.request.urlopen(req, timeout=20, context=_https_context(verify)) as resp:
                body = resp.read()
                return body, {k.lower(): v for k, v in resp.headers.items()}
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # DNS/edge propagation
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"could not fetch {url} within {timeout_s}s: {last_exc}")


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
