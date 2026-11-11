"""trust-store-revocation-add-describe-remove."""
from __future__ import annotations

import datetime
import time
from typing import Any

from behavioral_harness import tags

CHECK = "trust-store-revocation-add-describe-remove"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTrustStoreRevocations entries show up via DescribeTrustStoreRevocations and vanish after removal."""
    elbv2 = ctx.client("elbv2")

    ca_cert, ca_key, ca_pem, _ = _generate_self_signed_ca(ctx, "sim2real-ts-revocation-ca")
    bucket = _new_bucket_with_object(ctx, "ca-bundle.pem", ca_pem)

    ts_arn = elbv2.create_trust_store(
        Name=_ts_name(ctx, "sim2real-ts-"),
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-ts"}],
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _safe_delete_trust_store(elbv2, ts_arn))
    _wait_ts_active(elbv2, ts_arn)

    crl_pem = _generate_crl_pem(ca_cert, ca_key, revoked_serials=[123456789])
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="revoked.crl", Body=crl_pem)

    add_resp = elbv2.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"S3Bucket": bucket, "S3Key": "revoked.crl", "RevocationType": "CRL"}],
    )
    revocation = add_resp["TrustStoreRevocations"][0]
    revocation_id = revocation["RevocationId"]
    assert revocation["RevocationType"] == "CRL"
    assert revocation["NumberOfRevokedEntries"] == 1, revocation

    described = elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[revocation_id])[
        "TrustStoreRevocations"
    ]
    assert len(described) == 1
    assert described[0]["RevocationId"] == revocation_id
    assert described[0]["NumberOfRevokedEntries"] == 1

    all_revocations = elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"]
    assert any(r["RevocationId"] == revocation_id for r in all_revocations)

    elbv2.remove_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[revocation_id])

    code, message = _client_error(
        lambda: elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[revocation_id]),
        expect_error_for="describing a removed revocation id",
    )
    assert code == "RevocationIdNotFound", f"expected RevocationIdNotFound, got {code}"
    expected = f"Revocation ID '{revocation_id}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    remaining = elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"]
    assert all(r["RevocationId"] != revocation_id for r in remaining)

    second_remove_code, second_remove_message = _client_error(
        lambda: elbv2.remove_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[revocation_id]),
        expect_error_for="removing an already-removed revocation id",
    )
    assert second_remove_code == "RevocationIdNotFound", (
        f"removing an already-removed revocation id should still be rejected, got {second_remove_code}"
    )
    expected = f"Revocation ID '{revocation_id}' not found"
    assert second_remove_message == expected, f"expected message {expected!r}, got {second_remove_message!r}"


# ===== helpers =====
from botocore.exceptions import ClientError  # noqa: E402


def _client_error(fn, *, expect_error_for: str):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected {expect_error_for} to be rejected, but it succeeded")


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


def _generate_crl_pem(ca_cert, ca_key, revoked_serials=()) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
    )
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build()
        )
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    from cryptography.hazmat.primitives import serialization

    return crl.public_bytes(serialization.Encoding.PEM)


def _new_bucket_with_object(ctx, key: str, body: bytes) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2-ts-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1; this is an
        # S3 API quirk, not a pin of this check's own resource to that region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
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
