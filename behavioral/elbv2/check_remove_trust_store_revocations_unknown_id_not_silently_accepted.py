"""remove-trust-store-revocations-unknown-id-not-silently-accepted."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "remove-trust-store-revocations-unknown-id-not-silently-accepted"
GROUP = "overly-permissive"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RemoveTrustStoreRevocations with a never-added RevocationId fails with RevocationIdNotFound
    and leaves the remaining revocation intact; removing a real id succeeds."""
    elbv2 = ctx.client("elbv2")
    s3 = ctx.client("s3")

    ca_cert, ca_key, ca_pem = _generate_self_signed_ca()

    bucket = ctx.unique_name("sim2real-ts2-").lower().replace("_", "-")
    _create_bucket(ctx, bucket)
    s3.put_object(Bucket=bucket, Key="ca-bundle.pem", Body=ca_pem)

    name = ctx.unique_name("sim2real-truststore-")
    ts = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["TrustStores"][0]
    ts_arn = ts["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))

    _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=90,
        interval_s=3,
    )

    # CRL A is removed to show removal works for a real id; CRL B stays so the rejected call
    # has something it could disturb.
    crl_a = _generate_crl_pem(ca_cert, ca_key, revoked_serials=[111])
    crl_b = _generate_crl_pem(ca_cert, ca_key, revoked_serials=[222])
    s3.put_object(Bucket=bucket, Key="revoked-a.crl", Body=crl_a)
    s3.put_object(Bucket=bucket, Key="revoked-b.crl", Body=crl_b)

    # AddTrustStoreRevocations accepts one RevocationContents entry per call.
    added_a = elbv2.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"S3Bucket": bucket, "S3Key": "revoked-a.crl", "RevocationType": "CRL"}],
    )["TrustStoreRevocations"]
    added_b = elbv2.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"S3Bucket": bucket, "S3Key": "revoked-b.crl", "RevocationType": "CRL"}],
    )["TrustStoreRevocations"]
    assert len(added_a) == 1 and len(added_b) == 1, f"expected 1 revocation entry per call, got {added_a}, {added_b}"
    id_a, id_b = added_a[0]["RevocationId"], added_b[0]["RevocationId"]

    elbv2.remove_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[id_a])
    code_a, message_a = _error(
        lambda: elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[id_a])
    )
    assert code_a == "RevocationIdNotFound", (
        f"expected revocation {id_a} to be gone after a successful removal, got error code {code_a!r}"
    )
    expected_a = f"Revocation ID '{id_a}' not found"
    assert message_a == expected_a, f"expected message {expected_a!r}, got {message_a!r}"

    unknown_id = max(int(id_a), int(id_b)) + 999999
    code, message = _error(
        lambda: elbv2.remove_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[unknown_id])
    )
    assert code == "RevocationIdNotFound", (
        f"expected RevocationIdNotFoundException for an unknown/never-added revocation id, got {code}"
    )
    expected = f"Revocation ID '{unknown_id}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    remaining = elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[id_b])[
        "TrustStoreRevocations"
    ]
    assert len(remaining) == 1 and remaining[0]["RevocationId"] == id_b, (
        f"expected revocation {id_b} to survive the rejected removal of {unknown_id}, got {remaining}"
    )


# ===== helpers =====


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn(); return its error (code, message); an unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _create_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    kwargs: dict = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # us-east-1 rejects an explicit LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _generate_self_signed_ca():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-behavioral-test-ca")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert, key, cert_pem


def _generate_crl_pem(ca_cert, ca_key, revoked_serials=()) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    now = datetime.datetime.now(datetime.timezone.utc)
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
    return crl.public_bytes(serialization.Encoding.PEM)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
