"""trust-store-ca-bundle-server-side-validation-on-create."""
from __future__ import annotations

import datetime

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trust-store-ca-bundle-server-side-validation-on-create"
GROUP = "server-side"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrustStore validates the CA bundle synchronously: malformed PEM fails with
    InvalidCaCertificatesBundle, a missing S3 object with CaCertificatesBundleNotFound, and neither
    creates a trust store; a valid bundle succeeds as a positive control."""
    s3 = ctx.client("s3")
    elbv2 = ctx.client("elbv2")
    bucket = ctx.unique_name("sim2real-ts-").lower().replace("_", "-")
    _create_bucket(ctx, bucket)

    malformed_key = "malformed-ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=malformed_key, Body=b"this is not a certificate\n")

    # TrustStore names are limited to 32 characters; a longer name fails with ValidationError
    # before bundle validation runs.
    bad_name = ctx.unique_name("sim2real-ts-bad-")[:32].rstrip("-")
    code, message = _expect_bundle_rejected(ctx, elbv2, bad_name, bucket, malformed_key)
    assert code == "InvalidCaCertificatesBundle", (
        f"expected creating a trust store from malformed PEM content to be rejected "
        f"synchronously with InvalidCaCertificatesBundle, got {code!r}"
    )
    expected_message = "CA certificate bundle does not contain any certificates"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert not _trust_store_exists(elbv2, bad_name), (
        f"trust store {bad_name!r} should not exist after a rejected CreateTrustStore call"
    )

    missing_name = ctx.unique_name("sim2real-ts-miss-")[:32].rstrip("-")
    code2, message2 = _expect_bundle_rejected(ctx, elbv2, missing_name, bucket, "does/not/exist.pem")
    assert code2 == "CaCertificatesBundleNotFound", (
        f"expected creating a trust store from a missing S3 object to be rejected "
        f"synchronously with CaCertificatesBundleNotFound, got {code2!r}"
    )
    expected_message2 = "Provided CA certificate bundle was not found"
    assert message2 == expected_message2, f"expected message {expected_message2!r}, got {message2!r}"
    assert not _trust_store_exists(elbv2, missing_name), (
        f"trust store {missing_name!r} should not exist after a rejected CreateTrustStore call"
    )

    # Positive control: without it, both rejections are indistinguishable from rejecting every call.
    good_key = "good-ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=good_key, Body=_generate_self_signed_ca_pem())
    good_name = ctx.unique_name("sim2real-ts-good-")[:32].rstrip("-")
    created = elbv2.create_trust_store(
        Name=good_name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key=good_key,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TrustStores"][0]
    good_arn = created["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=good_arn))
    assert created["Status"] in ("CREATING", "ACTIVE"), (
        f"expected creating a trust store from a valid, reachable CA bundle to succeed, "
        f"got status {created['Status']!r}"
    )
    described = elbv2.describe_trust_stores(TrustStoreArns=[good_arn])["TrustStores"]
    assert described and described[0]["Name"] == good_name, (
        f"expected the successfully created trust store {good_arn!r} to be visible via an "
        f"independent DescribeTrustStores read, got {described!r}"
    )


def _expect_bundle_rejected(ctx, elbv2, name: str, bucket: str, key: str) -> tuple[str, str]:
    """Call CreateTrustStore expecting a synchronous bundle rejection; return (code, message).
    An unexpectedly created trust store is scheduled for cleanup so it cannot leak."""
    try:
        resp = elbv2.create_trust_store(
            Name=name,
            CaCertificatesBundleS3Bucket=bucket,
            CaCertificatesBundleS3Key=key,
        )
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    arn = resp["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_trust_store(TrustStoreArn=arn)))
    raise AssertionError(
        f"expected CreateTrustStore with bucket={bucket!r} key={key!r} to be rejected, "
        f"but it succeeded and created {arn}"
    )


def _trust_store_exists(elbv2, name: str) -> bool:
    try:
        resp = elbv2.describe_trust_stores(Names=[name])
    except botocore.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] in ("TrustStoreNotFound", "TrustStoreNotFoundException"):
            return False
        raise
    return bool(resp.get("TrustStores"))


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrustStoreNotFound":
            raise


def _generate_self_signed_ca_pem() -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-ts-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
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
    return cert.public_bytes(serialization.Encoding.PEM)


def _create_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    kwargs: dict = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region where S3 rejects an explicit
        # LocationConstraint on CreateBucket -- it must be omitted there.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
