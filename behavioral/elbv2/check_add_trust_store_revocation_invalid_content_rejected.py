"""add-trust-store-revocation-invalid-content-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "add-trust-store-revocation-invalid-content-rejected"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTrustStoreRevocations with content that is not a CRL fails with InvalidRevocationContent and the exact
    message and adds no revocation, while a valid CRL then adds one revoked entry."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    ca_key, ca_cert, ca_pem = _make_ca(x509, hashes, rsa, NameOID, serialization)
    bucket = _create_bucket(ctx)
    ca_key_name = "ca-bundle.pem"
    _put(ctx, bucket, ca_key_name, ca_pem)

    elbv2 = ctx.client("elbv2")
    ts_name = ctx.unique_name("sim2real-ts-")[:32].rstrip("-")
    ts = elbv2.create_trust_store(
        Name=ts_name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key=ca_key_name,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-ts"}],
    )["TrustStores"][0]
    ts_arn = ts["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))
    _wait_trust_store_active(ctx, ts_arn)

    garbage_key_name = "garbage.txt"
    _put(ctx, bucket, garbage_key_name, b"this is not a certificate revocation list")

    # A non-CRL object is rejected. A just-written object can answer RevocationContentNotFound
    # until it is visible to the service, so the add is retried on that code before the
    # InvalidRevocationContent rejection is asserted.
    code, message = _retry_add_revocation_error_code(
        elbv2, ts_arn, bucket, garbage_key_name, attempts=3, delay_s=5.0
    )
    assert code == "InvalidRevocationContent", f"expected InvalidRevocationContent, got {code}"
    expected_message = "Provided revocation file is not in the correct format"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    revocations = elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"]
    assert revocations == [], f"the rejected revocation must not have been added, got {revocations}"
    total = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]["TotalRevokedEntries"]
    assert total == 0

    # Positive control: a genuinely valid CRL against the same trust store succeeds. The S3
    # object was just written, so retry on RevocationContentNotFound to absorb read-after-write
    # propagation delay rather than treating it as a hard failure.
    crl_pem = _make_crl(x509, hashes, serialization, ca_key, ca_cert, revoked_serial=13579)
    crl_key_name = "revocation.pem"
    _put(ctx, bucket, crl_key_name, crl_pem)
    add_resp = _add_revocation_with_retry(
        elbv2, ts_arn, bucket, crl_key_name, attempts=6, delay_s=5.0
    )
    assert add_resp["TrustStoreRevocations"][0]["NumberOfRevokedEntries"] == 1
    total_after = _wait_total_revoked(ctx, ts_arn, expected=1)
    assert total_after == 1


def _add_revocation_with_retry(elbv2, ts_arn, bucket, key_name, attempts: int, delay_s: float):
    last_exc = None
    for _ in range(attempts):
        try:
            return elbv2.add_trust_store_revocations(
                TrustStoreArn=ts_arn,
                RevocationContents=[{"S3Bucket": bucket, "S3Key": key_name, "RevocationType": "CRL"}],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RevocationContentNotFound":
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _retry_add_revocation_error_code(elbv2, ts_arn, bucket, key_name, attempts: int, delay_s: float):
    """Like _add_revocation_with_retry but returns the final (code, message) instead of raising,
    for a call that is expected to fail permanently (garbage content). An accepted call raises."""
    code = message = None
    for _ in range(attempts):
        try:
            result = elbv2.add_trust_store_revocations(
                TrustStoreArn=ts_arn,
                RevocationContents=[{"S3Bucket": bucket, "S3Key": key_name, "RevocationType": "CRL"}],
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
            if code != "RevocationContentNotFound":
                return code, message
            time.sleep(delay_s)
            continue
        raise AssertionError(f"expected the garbage revocation content to be rejected, but it was added: {result!r}")
    return code, message


def _make_ca(x509, hashes, rsa, NameOID, serialization):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-elbv2-negcrl-ca")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert, cert.public_bytes(serialization.Encoding.PEM)


def _make_crl(x509, hashes, serialization, ca_key, ca_cert, revoked_serial: int) -> bytes:
    now = datetime.datetime.utcnow()
    revoked = (
        x509.RevokedCertificateBuilder().serial_number(revoked_serial).revocation_date(now).build()
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
        .add_revoked_certificate(revoked)
        .sign(ca_key, hashes.SHA256())
    )
    return crl.public_bytes(serialization.Encoding.PEM)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2-negcrl-").lower().replace("_", "-")
    kwargs: dict = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup_bucket() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
    return bucket


def _put(ctx, bucket: str, key_name: str, content: bytes) -> None:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key_name, Body=content)


def _wait_trust_store_active(ctx, ts_arn: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        ts = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]
        last = ts["Status"]
        if last == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"trust store never became ACTIVE, last status={last}")


def _wait_total_revoked(ctx, ts_arn: str, expected: int, timeout_s: float = 60.0, interval_s: float = 3.0) -> int:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = -1
    while time.monotonic() < deadline:
        ts = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]
        last = ts["TotalRevokedEntries"]
        if last >= expected:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"TotalRevokedEntries never reached {expected} within {timeout_s}s, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
