"""list-distributions-by-trust-store-consistency."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "list-distributions-by-trust-store-consistency"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A distribution whose DistributionConfig.ViewerMtlsConfig references a trust store
    appears in ListDistributionsByTrustStore for that trust store's id.
    """
    bucket, key = _upload_ca_bundle(ctx)
    trust_store_id = _create_trust_store(ctx, bucket, key)
    dist_id = _create_mtls_distribution(ctx, trust_store_id)

    ids = _poll_ids_by_trust_store(ctx, trust_store_id, dist_id, timeout_s=180.0)
    assert dist_id in ids, "distribution configured with the trust store never appeared in ListDistributionsByTrustStore"


def _generate_self_signed_ca_pem() -> str:
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        key_path = Path(d) / "ca-key.pem"
        cert_path = Path(d) / "ca-cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "2", "-nodes", "-subj", "/CN=sim2real-cloudfront-trust-store-test",
            ],
            check=True,
            capture_output=True,
        )
        return cert_path.read_text()


def _upload_ca_bundle(ctx):
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-cf-trust-").lower().replace("_", "-")
    key = "ca-bundle.pem"
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket, key))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"Service":"cloudfront.amazonaws.com"},'
            '"Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/%s",'
            '"Condition":{"StringEquals":{"aws:SourceAccount":"%s"}}}]}'
        )
        % (bucket, key, account_id),
    )
    pem = _generate_self_signed_ca_pem()
    s3.put_object(Bucket=bucket, Key=key, Body=pem.encode("utf-8"))
    return bucket, key


def _delete_bucket(ctx, bucket: str, key: str) -> None:
    s3 = ctx.client("s3")
    try:
        s3.delete_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_trust_store(ctx, bucket: str, key: str, timeout_s: float = 120.0) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_trust_store(
        Name=ctx.unique_name("sim2real-cf-ts-"),
        CaCertificatesBundleSource={
            "CaCertificatesBundleS3Location": {"Bucket": bucket, "Key": key, "Region": ctx.region}
        },
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    trust_store_id = resp["TrustStore"]["Id"]
    ctx.on_cleanup(lambda: _delete_trust_store(ctx, trust_store_id))

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = cf.get_trust_store(Identifier=trust_store_id)
        status = got["TrustStore"]["Status"]
        if status == "active":
            return trust_store_id
        if status == "failed":
            raise AssertionError(f"trust store creation failed: {got['TrustStore'].get('Reason')}")
        time.sleep(5)
    raise AssertionError("trust store never reached 'active' status within timeout")


def _delete_trust_store(ctx, trust_store_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        got = cf.get_trust_store(Identifier=trust_store_id)
        cf.delete_trust_store(Id=trust_store_id, IfMatch=got["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


def _create_mtls_distribution(ctx, trust_store_id: str) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": ctx.unique_name("sim2real-cf-mtls-"),
                "Comment": "sim2real trust-store test distribution",
                "Enabled": True,
                "HttpVersion": "http2",
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "test-origin",
                            "DomainName": "www.example.com",
                            "CustomOriginConfig": {
                                "HTTPPort": 80,
                                "HTTPSPort": 443,
                                "OriginProtocolPolicy": "https-only",
                                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                            },
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": "test-origin",
                    "ViewerProtocolPolicy": "https-only",
                    "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
                },
                "ViewerMtlsConfig": {
                    "Mode": "optional",
                    "TrustStoreConfig": {"TrustStoreId": trust_store_id},
                },
            },
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    return dist_id


def _disable_and_delete_distribution(ctx, dist_id: str, timeout_s: float = 900.0) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    dist_config = cfg_resp["DistributionConfig"]
    if dist_config.get("Enabled"):
        dist_config["Enabled"] = False
        try:
            cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=dist_config)
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
    deadline = time.monotonic() + timeout_s
    etag = None
    while time.monotonic() < deadline:
        try:
            got = cf.get_distribution(Id=dist_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchDistribution":
                raise
            return
        if got["Distribution"]["Status"] == "Deployed":
            etag = got["ETag"]
            break
        time.sleep(15)
    if etag is None:
        return
    try:
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise


def _poll_ids_by_trust_store(ctx, trust_store_id: str, dist_id: str, timeout_s: float = 120.0) -> set:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    ids: set = set()
    while time.monotonic() < deadline:
        resp = cf.list_distributions_by_trust_store(TrustStoreIdentifier=trust_store_id)
        ids = {item["Id"] for item in resp.get("DistributionList", {}).get("Items", []) or []}
        if dist_id in ids:
            return ids
        time.sleep(5)
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
