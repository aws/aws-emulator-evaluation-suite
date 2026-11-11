"""modify-trust-store-missing-bundle-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "modify-trust-store-missing-bundle-rejected"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyTrustStore with a nonexistent S3 bundle key raises CaCertificatesBundleNotFoundException
    and leaves the CA bundle and ACTIVE status untouched; a modify with a valid bundle then succeeds."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    ca_pem = _make_ca_bundle(x509, hashes, rsa, NameOID, serialization, "sim2real-elbv2-negmod-ca-1")
    bucket = _create_bucket(ctx)
    ca_key_name = "ca-bundle-1.pem"
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

    before = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]
    assert before["Status"] == "ACTIVE", f"trust store must be ACTIVE before the negative modify, got {before['Status']}"
    ca_count_before = before["NumberOfCaCertificates"]

    missing_key = "does-not-exist-" + ts_name + ".pem"
    code, message = _error(
        lambda: elbv2.modify_trust_store(
            TrustStoreArn=ts_arn,
            CaCertificatesBundleS3Bucket=bucket,
            CaCertificatesBundleS3Key=missing_key,
        )
    )
    assert code == "CaCertificatesBundleNotFound", f"expected CaCertificatesBundleNotFound, got {code}"
    expected = "Provided CA certificate bundle was not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]
    assert after["Status"] == "ACTIVE", f"trust store must remain ACTIVE after a rejected modify, got {after['Status']}"
    assert after["NumberOfCaCertificates"] == ca_count_before, (
        f"CA cert count must be unchanged after a rejected modify, "
        f"was {ca_count_before}, now {after['NumberOfCaCertificates']}"
    )

    # Positive control: modifying with a genuinely valid bundle succeeds and settles back to
    # ACTIVE. The S3 object was just written, so retry on CaCertificatesBundleNotFound to
    # absorb read-after-write propagation delay rather than treating it as a hard failure.
    ca_pem_2 = _make_ca_bundle(x509, hashes, rsa, NameOID, serialization, "sim2real-elbv2-negmod-ca-2")
    ca_key_name_2 = "ca-bundle-2.pem"
    _put(ctx, bucket, ca_key_name_2, ca_pem_2)
    _modify_trust_store_with_retry(elbv2, ts_arn, bucket, ca_key_name_2, attempts=6, delay_s=5.0)
    _wait_trust_store_active(ctx, ts_arn, timeout_s=60.0)
    final = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]
    assert final["Status"] == "ACTIVE", f"trust store must settle back to ACTIVE after a valid modify, got {final['Status']}"


# ===== helpers =====


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a bundle reference real AWS refuses is the strongest signal
    available and must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ModifyTrustStore to reject the missing bundle, but it SUCCEEDED and returned {result!r}")


def _modify_trust_store_with_retry(elbv2, ts_arn, bucket, key_name, attempts: int, delay_s: float):
    last_exc = None
    for _ in range(attempts):
        try:
            return elbv2.modify_trust_store(
                TrustStoreArn=ts_arn, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key=key_name
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "CaCertificatesBundleNotFound":
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _make_ca_bundle(x509, hashes, rsa, NameOID, serialization, common_name: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
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
    return cert.public_bytes(serialization.Encoding.PEM)


def _upload(ctx, key_name: str, content: bytes) -> tuple[str, str]:
    bucket = _create_bucket(ctx)
    _put(ctx, bucket, key_name, content)
    return bucket, key_name


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2-negmod-").lower().replace("_", "-")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
