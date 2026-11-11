"""create-trust-store-duplicate-name-fails."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "create-trust-store-duplicate-name-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrustStore with a name already in use fails with DuplicateTrustStoreName and the exact message, and
    exactly one trust store of that name remains."""

    _run(ctx)


def _run(ctx) -> None:
    elbv2 = ctx.client("elbv2")
    bundle = _generate_self_signed_ca_pem()
    bucket, key = _create_ca_bundle_object(ctx, bundle)

    name = _short_alnum_name(ctx, "sim2real-dup")
    ts = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key=key,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["TrustStores"][0]
    ts_arn = ts["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))

    # Positive control: the valid creation above succeeded and is visible exactly once.
    listing = elbv2.describe_trust_stores(Names=[name])["TrustStores"]
    assert len(listing) == 1 and listing[0]["TrustStoreArn"] == ts_arn, (
        f"expected exactly one trust store {ts_arn!r} named {name!r}, got {listing!r}"
    )

    code, message = _error(
        lambda: elbv2.create_trust_store(
            Name=name,
            CaCertificatesBundleS3Bucket=bucket,
            CaCertificatesBundleS3Key=key,
        )
    )
    assert code == "DuplicateTrustStoreName", f"expected DuplicateTrustStoreName, got {code}"
    assert message == f"A trust store with the name '{name}' already exists", f"MSG={message!r}"

    # The forbidden effect (a second trust store) did not happen: still exactly one.
    listing_after = elbv2.describe_trust_stores(Names=[name])["TrustStores"]
    assert len(listing_after) == 1 and listing_after[0]["TrustStoreArn"] == ts_arn, (
        f"expected exactly one trust store {ts_arn!r} named {name!r} after the rejected "
        f"duplicate create, got {listing_after!r}"
    )


run.__wrapped_by_tags__ = True


def _short_alnum_name(ctx, prefix: str, max_len: int = 32) -> str:
    raw = ctx.unique_name(f"{prefix}-").replace("_", "-").lower()
    if len(raw) > max_len:
        raw = raw[-max_len:]
    raw = raw.strip("-")
    return raw


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Run ``fn``, which AWS refuses, and return the refusal's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _generate_self_signed_ca_pem() -> bytes:

    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-test-ca")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _create_ca_bundle_object(ctx, body: bytes, key: str = "ca-bundle.pem"):
    s3 = ctx.client("s3")
    bucket = _short_alnum_name(ctx, "sim2real-elbv2-ts", max_len=63)
    region = ctx.region
    if region == "us-east-1":
        # us-east-1 is the S3 API's default region: passing a LocationConstraint for it is rejected.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    return bucket, key


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
