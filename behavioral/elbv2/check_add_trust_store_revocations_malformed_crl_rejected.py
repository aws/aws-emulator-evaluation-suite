"""add-trust-store-revocations-malformed-crl-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "add-trust-store-revocations-malformed-crl-rejected"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddTrustStoreRevocations rejects a revocation file that is not a valid CRL with
    InvalidRevocationContent and adds no revocation entry; the same trust store then
    accepts a well-formed CRL signed by its own CA (positive control)."""
    import cryptography  # noqa: F401

    elbv2 = ctx.client("elbv2")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    ca_pem, _, ca_key, ca_cert = _self_signed_cert_and_key("sim2real-elbv2-badcrl-ca")
    s3.put_object(Bucket=bucket, Key="ca-bundle.pem", Body=ca_pem)
    # Not a CRL at all -- arbitrary bytes uploaded under a plausible key name.
    s3.put_object(Bucket=bucket, Key="not-a-crl.pem", Body=b"this is definitely not a CRL file\n")

    name = ctx.unique_name("sim2real-ts-badcrl-")[:32]
    ts_arn = _create_trust_store_retrying(ctx, elbv2, name, bucket, "ca-bundle.pem")["TrustStoreArn"]

    def _cleanup_ts():
        try:
            elbv2.delete_trust_store(TrustStoreArn=ts_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TrustStoreNotFound":
                raise

    ctx.on_cleanup(_cleanup_ts)

    _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )

    code, message = _error_code(
        lambda: elbv2.add_trust_store_revocations(
            TrustStoreArn=ts_arn,
            RevocationContents=[{"S3Bucket": bucket, "S3Key": "not-a-crl.pem", "RevocationType": "CRL"}],
        )
    )
    assert code == "InvalidRevocationContent", f"expected InvalidRevocationContent, got {code}"
    expected_message = "Provided revocation file is not in the correct format"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Forbidden effect did not happen: no revocation entry was recorded.
    revs = elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"]
    assert revs == [], f"expected no revocation entries after a rejected add, got {revs}"

    # Positive control: a well-formed CRL signed by this trust store's own CA is accepted.
    crl_pem = _build_crl_pem(ca_key, ca_cert, revoked_serial=99)
    s3.put_object(Bucket=bucket, Key="valid.crl.pem", Body=crl_pem)
    added = elbv2.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"S3Bucket": bucket, "S3Key": "valid.crl.pem", "RevocationType": "CRL"}],
    )["TrustStoreRevocations"]
    assert len(added) == 1
    revocation_id = added[0]["RevocationId"]
    revs_after = _poll_until(
        lambda: elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"],
        lambda rs: any(r["RevocationId"] == revocation_id for r in rs),
        timeout_s=60,
        interval_s=3,
    )
    assert any(r["RevocationId"] == revocation_id for r in revs_after)


def _create_trust_store_retrying(ctx, elbv2, name: str, bucket: str, key: str) -> dict:
    """Trust stores are a low account-wide quota, and other checks in this same suite
    concurrently create and delete their own trust stores against it, so CreateTrustStore can
    transiently hit TooManyTrustStoresException. Retry (bounded) on that specific error; this
    deletes nothing, since each check deletes only the trust store it created."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 600.0
    while True:
        try:
            return elbv2.create_trust_store(
                Name=name,
                CaCertificatesBundleS3Bucket=bucket,
                CaCertificatesBundleS3Key=key,
                Tags=[
                    {"Key": "sim2real:managed", "Value": "true"},
                    {"Key": "sim2real:prefix", "Value": "sim2real-ts-badcrl"},
                ],
            )["TrustStores"][0]
        except ClientError as err:
            if err.response["Error"]["Code"] != "TooManyTrustStores" or time.monotonic() >= deadline:
                raise
            time.sleep(15)


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2-badcrl").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for o in objs:
                s3.delete_object(Bucket=bucket, Key=o["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _self_signed_cert_and_key(common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem, key, cert


def _build_crl_pem(ca_key, ca_cert, revoked_serial: int) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    now = datetime.datetime.utcnow()
    revoked = x509.RevokedCertificateBuilder().serial_number(revoked_serial).revocation_date(now).build()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=365))
        .add_revoked_certificate(revoked)
    )
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

