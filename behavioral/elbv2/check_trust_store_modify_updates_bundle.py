"""trust-store-modify-updates-bundle."""
from __future__ import annotations

import datetime
import time
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "trust-store-modify-updates-bundle"
GROUP = "state-machine"
SERVICES = ["elbv2"]

_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """ModifyTrustStore replaces the CA bundle; the change is reflected in DescribeTrustStores/Get*Bundle."""
    elbv2 = ctx.client("elbv2")

    _, _, ca1_pem, _ = _generate_self_signed_ca(ctx, "sim2real-ts-modify-ca1")
    bucket = _new_bucket_with_object(ctx, "ca-bundle-v1.pem", ca1_pem)

    ts_arn = elbv2.create_trust_store(
        Name=_ts_name(ctx, "sim2real-ts-"),
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle-v1.pem",
        Tags=_TAGS,
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _safe_delete_trust_store(elbv2, ts_arn))

    ts = _wait_ts_active(elbv2, ts_arn)
    assert ts["NumberOfCaCertificates"] == 1, ts

    # bundle v2 has TWO certificates concatenated -> an observable, countable change
    _, _, ca2a_pem, _ = _generate_self_signed_ca(ctx, "sim2real-ts-modify-ca2a")
    _, _, ca2b_pem, _ = _generate_self_signed_ca(ctx, "sim2real-ts-modify-ca2b")
    bundle_v2 = ca2a_pem + ca2b_pem
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="ca-bundle-v2.pem", Body=bundle_v2)

    modify_resp = elbv2.modify_trust_store(
        TrustStoreArn=ts_arn, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key="ca-bundle-v2.pem"
    )
    assert modify_resp["TrustStores"][0]["TrustStoreArn"] == ts_arn

    ts_after = _wait_ts_active(elbv2, ts_arn)
    assert ts_after["NumberOfCaCertificates"] == 2, ts_after

    location = elbv2.get_trust_store_ca_certificates_bundle(TrustStoreArn=ts_arn)["Location"]
    _url, _route = ctx.endpoint_route(location)
    with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=30) as resp:  # noqa: S310
        downloaded = resp.read()
    assert downloaded.count(b"-----BEGIN CERTIFICATE-----") == 2, downloaded
    assert downloaded == bundle_v2, (
        f"served bundle ({len(downloaded)} bytes) does not byte-match the uploaded "
        f"concatenated v2 bundle ({len(bundle_v2)} bytes) after modify"
    )
    assert downloaded != ca1_pem


# ===== helpers =====
from botocore.exceptions import ClientError  # noqa: E402


def _ts_name(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _generate_self_signed_ca(ctx, common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert, key, cert_pem, key_pem


def _new_bucket_with_object(ctx, key: str, body: bytes) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2-ts-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _safe_delete_trust_store(elbv2, arn: str) -> None:
    try:
        elbv2.delete_trust_store(TrustStoreArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrustStoreNotFoundException":
            raise


def _wait_ts_active(elbv2, arn: str, timeout_s: float = 90.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = elbv2.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]
        if last["Status"] == "ACTIVE":
            return last
        if last["Status"] not in ("CREATING", "ACTIVE"):
            raise AssertionError(f"unexpected trust store status: {last['Status']}")
        time.sleep(2)
    raise AssertionError(f"trust store did not become ACTIVE within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
