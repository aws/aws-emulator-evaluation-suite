"""server-side-origin-access-control-signs-requests."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from behavioral_harness import tags

CHECK = "server-side-origin-access-control-signs-requests"
GROUP = "server-side"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With an OAC on the S3 origin and a bucket policy trusting only the distribution's ARN, a direct unsigned GET
    of the object answers 403 AccessDenied without its bytes while a GET through the distribution returns the
    object, so CloudFront SigV4-signs the origin request."""
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-oac-bucket-")
    _create_bucket(ctx, s3, bucket)
    key = "test-object.txt"
    body_text = "hello-from-oac-origin"
    s3.put_object(Bucket=bucket, Key=key, Body=body_text.encode("utf-8"))

    oac_id = _create_oac(ctx, cf)

    domain_name = f"{bucket}.s3.{ctx.region}.amazonaws.com"
    dist_id, dist_domain, dist_arn = _create_s3_distribution(ctx, cf, domain_name, oac_id)

    _apply_bucket_policy_for_distribution(ctx, s3, bucket, dist_arn)
    _wait_for_deployed(cf, dist_id)

    # Positive control: the object exists and is readable with the check's credentials, so
    # the direct-access denial below can only be about who is asking, never about the object.
    assert s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8") == body_text, (
        "the signed GetObject did not return the object that was uploaded"
    )

    # Direct, unsigned access to the object must be denied with S3's specific error, not just
    # any non-200 -- and the denial body must not leak the object's bytes.
    s3_endpoint = (s3.meta.endpoint_url or "").rstrip("/")
    direct_url = f"{s3_endpoint}/{bucket}/{key}"
    direct_status, direct_body = _http_status_and_body(direct_url, verify=ctx.http_verify)
    assert direct_status == 403, (
        f"expected direct unsigned S3 access to be denied (403), got {direct_status}: {direct_body[:200]!r}"
    )
    direct_code = ET.fromstring(direct_body).findtext("Code") if direct_body.startswith(b"<") else None
    assert direct_code == "AccessDenied", (
        f"expected AccessDenied from S3 on direct access, got {direct_code!r}: {direct_body[:200]!r}"
    )
    assert body_text.encode("utf-8") not in direct_body, (
        f"the S3 403 body leaked the object's bytes: {direct_body[:200]!r}"
    )

    # Access through the distribution (which CloudFront signs) must succeed
    # and return the exact object content.
    edge, route = ctx.endpoint_route(dist_domain)
    body, _ = _fetch(f"{edge}/{key}", route, verify=ctx.http_verify)
    assert body.decode("utf-8") == body_text, f"unexpected body via distribution: {body!r}"


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_oac(ctx, cf) -> str:
    name = ctx.unique_name("sim2real-oac-")
    resp = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": name,
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


def _create_s3_distribution(ctx, cf, domain_name: str, oac_id: str):
    origin_id = ctx.unique_name("sim2real-origin-")
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": ctx.unique_name("sim2real-dist-"),
                "Comment": "sim2real behavioral check",
                "Enabled": True,
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": origin_id,
                            "DomainName": domain_name,
                            "OriginAccessControlId": oac_id,
                            "S3OriginConfig": {"OriginAccessIdentity": ""},
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": origin_id,
                    "ViewerProtocolPolicy": "allow-all",
                    "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
                },
            },
            "Tags": {"Items": [{"Key": "sim2real", "Value": "true"}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    domain = resp["Distribution"]["DomainName"]
    arn = resp["Distribution"]["ARN"]
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))
    return dist_id, domain, arn


def _apply_bucket_policy_for_distribution(ctx, s3, bucket: str, dist_arn: str) -> None:
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
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


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
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        dist = cf.get_distribution(Id=dist_id)
        if dist["Distribution"]["Status"] == "Deployed":
            etag = dist["ETag"]
            break
        time.sleep(15)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _http_status_and_body(url: str, timeout_s: float = 60.0, verify=True) -> tuple[int, bytes]:
    """Bounded retry so a transient DNS/connection blip right after CreateBucket does not
    read as a fidelity result; the deny itself is not eventually-consistent."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=20, context=_https_context(verify)) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # DNS/connection blip
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"could not reach {url} within {timeout_s}s: {last_exc}")


def _fetch(url: str, route: dict, timeout_s: float = 600.0, verify=True):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=route), timeout=20, context=_https_context(verify)) as resp:
                return resp.read(), {k.lower(): v for k, v in resp.headers.items()}
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
