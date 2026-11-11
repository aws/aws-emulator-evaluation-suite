"""cloudfront-s3-signed-url-restricted-access-positive."""
from __future__ import annotations

import datetime
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudfront-s3-signed-url-restricted-access-positive"
GROUP = "origin-access-control"
SERVICES = ["apigateway", "cloudfront", "s3"]

_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFront cache behavior with a required trusted key group rejects
    unsigned viewer requests and only serves the S3 origin object when the
    request carries a valid CloudFront URL signature."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from botocore.signers import CloudFrontSigner

    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    bucket = ctx.unique_name("sim2real-signedurl-")
    key = "protected.txt"
    body = f"protected-content-{uuid.uuid4()}".encode()

    _create_private_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain")

    oac_id = _create_oac(ctx, cf, ctx.unique_name("sim2real-oac-cfg-"))

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    public_key_id = _create_public_key(ctx, cf, public_key_pem)
    key_group_id = _create_key_group(ctx, cf, [public_key_id])

    origin_id = "s3-origin"
    dist_cfg = {
        "CallerReference": str(uuid.uuid4()),
        "Comment": "sim2real-signed-url-restricted-access-positive",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                    "OriginAccessControlId": oac_id,
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _CACHING_DISABLED_POLICY_ID,
            "TrustedKeyGroups": {"Enabled": True, "Quantity": 1, "Items": [key_group_id]},
        },
    }
    dist = cf.create_distribution(DistributionConfig=dist_cfg)["Distribution"]
    dist_id = dist["Id"]
    dist_arn = dist["ARN"]
    domain = dist["DomainName"]
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, cf, dist_id))

    s3.put_bucket_policy(Bucket=bucket, Policy=_oac_bucket_policy(bucket, dist_arn))

    _wait_distribution_deployed(ctx, cf, dist_id, timeout_s=1500.0)

    unsigned_url, edge_headers = ctx.endpoint_route(f"{domain}/{key}")
    published_url = f"{urllib.parse.urlsplit(unsigned_url).scheme}://{domain}/{key}"

    def _rsa_signer(message: bytes) -> bytes:
        return private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())

    signer = CloudFrontSigner(public_key_id, _rsa_signer)
    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    # The signature covers the URL CloudFront publishes; the request goes where ctx routes it.
    signed_url, _ = ctx.endpoint_route(
        signer.generate_presigned_url(published_url, date_less_than=expire)
    )

    # Unsigned requests must be rejected once a trusted key group is required.
    unsigned_status, unsigned_body = _poll_http_get(
        unsigned_url, lambda s, b: s == 403, timeout_s=300.0, interval_s=10.0, headers=edge_headers, verify=ctx.http_verify
    )
    assert unsigned_status == 403, f"expected 403 for unsigned request once TrustedKeyGroups is enforced, got {unsigned_status}: {unsigned_body!r}"

    # A validly signed URL for the same object must succeed and return the real content.
    signed_status, signed_body = _poll_http_get(
        signed_url, lambda s, b: s == 200 and b == body, timeout_s=180.0, interval_s=10.0, headers=edge_headers, verify=ctx.http_verify
    )
    assert signed_status == 200, f"expected 200 for a validly signed URL, got {signed_status}: {signed_body!r}"
    assert signed_body == body, "content served via a validly signed CloudFront URL did not match the S3 object"


def _create_private_bucket(ctx, s3, name: str) -> str:
    kwargs = {"Bucket": name}
    # us-east-1 is CreateBucket's own default region and rejects an explicit
    # LocationConstraint for it; every other region requires one.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, name))
    return name


def _empty_and_delete_bucket(ctx, s3, name: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_oac(ctx, cf, name: str) -> str:
    resp = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": name,
            "Description": "sim2real behavioral check",
            "SigningProtocol": "sigv4",
            "SigningBehavior": "always",
            "OriginAccessControlOriginType": "s3",
        }
    )
    oac_id = resp["OriginAccessControl"]["Id"]

    def _cleanup():
        try:
            etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
            cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchOriginAccessControl":
                raise

    ctx.on_cleanup(_cleanup)
    return oac_id


def _create_public_key(ctx, cf, public_key_pem: str) -> str:
    resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": str(uuid.uuid4()),
            "Name": ctx.unique_name("sim2real-pubkey-"),
            "EncodedKey": public_key_pem,
            "Comment": "sim2real behavioral check",
        }
    )
    key_id = resp["PublicKey"]["Id"]

    def _cleanup():
        try:
            etag = cf.get_public_key(Id=key_id)["ETag"]
            cf.delete_public_key(Id=key_id, IfMatch=etag)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchPublicKey":
                raise

    ctx.on_cleanup(_cleanup)
    return key_id


def _create_key_group(ctx, cf, public_key_ids: list) -> str:
    resp = cf.create_key_group(
        KeyGroupConfig={
            "Name": ctx.unique_name("sim2real-keygroup-"),
            "Items": public_key_ids,
            "Comment": "sim2real behavioral check",
        }
    )
    group_id = resp["KeyGroup"]["Id"]

    def _cleanup():
        try:
            etag = cf.get_key_group(Id=group_id)["ETag"]
            cf.delete_key_group(Id=group_id, IfMatch=etag)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchResource":
                raise

    ctx.on_cleanup(_cleanup)
    return group_id


def _oac_bucket_policy(bucket: str, distribution_arn: str) -> str:
    import json

    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowCloudFrontServicePrincipalOAC",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudfront.amazonaws.com"},
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                    "Condition": {"StringEquals": {"AWS:SourceArn": distribution_arn}},
                }
            ],
        }
    )


def _wait_distribution_deployed(ctx, cf, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s (last={status})")


def _disable_and_delete_distribution(ctx, cf, dist_id: str) -> None:
    try:
        resp = cf.get_distribution_config(Id=dist_id)
        cfg = resp["DistributionConfig"]
        etag = resp["ETag"]
        if cfg.get("Enabled"):
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, DistributionConfig=cfg, IfMatch=etag)
            _wait_distribution_deployed(ctx, cf, dist_id, timeout_s=1500.0)
        etag = cf.get_distribution(Id=dist_id)["ETag"]
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFound",
            "NoSuchCachePolicy",
            "NoSuchContinuousDeploymentPolicy",
            "NoSuchDistribution",
            "NoSuchFieldLevelEncryptionConfig",
            "NoSuchOrigin",
            "NoSuchOriginRequestPolicy",
            "NoSuchRealtimeLogConfig",
            "NoSuchResponseHeadersPolicy",
            "TrustedKeyGroupDoesNotExist",
            "TrustedSignerDoesNotExist",
        ):
            raise


def _http_get(url: str, timeout: float = 15.0, headers: dict[str, str] | None = None, verify=True):
    try:
        request = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(request, timeout=timeout, context=_https_context(verify)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        return None, str(e).encode()


def _poll_http_get(
    url: str, predicate, timeout_s: float = 180.0, interval_s: float = 10.0, headers: dict[str, str] | None = None, verify=True
):
    deadline = time.monotonic() + timeout_s
    status, body = None, b""
    while time.monotonic() < deadline:
        status, body = _http_get(url, headers=headers, verify=verify)
        if predicate(status, body):
            return status, body
        time.sleep(interval_s)
    return status, body


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
