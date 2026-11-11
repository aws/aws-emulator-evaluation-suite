"""get-trust-store-ca-bundle-unknown-truststore-fails."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-trust-store-ca-bundle-unknown-truststore-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTrustStoreCaCertificatesBundle succeeds for a real, ACTIVE trust store
    (positive control) but raises TrustStoreNotFoundException for a well-formed ARN
    pointing at a trust store that was never created."""
    elbv2 = ctx.client("elbv2")
    s3 = ctx.client("s3")

    ca_cert_pem = _generate_ca_pem()
    bucket = _create_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="ca-bundle.pem", Body=ca_cert_pem)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="ca-bundle.pem"))

    ts_arn = elbv2.create_trust_store(
        Name=ctx.unique_name("sim2real-ts-")[:32].rstrip("-"),
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _delete_trust_store_safe(elbv2, ts_arn))
    _wait_trust_store_status(elbv2, ts_arn, "ACTIVE", timeout_s=120)

    control = elbv2.get_trust_store_ca_certificates_bundle(TrustStoreArn=ts_arn)
    assert control.get("Location"), (
        f"positive control: expected a Location for the real, ACTIVE trust store "
        f"{ts_arn!r}, got {control!r}"
    )

    fake_arn = _fake_trust_store_arn(ctx)
    code, message = _error(
        lambda: elbv2.get_trust_store_ca_certificates_bundle(TrustStoreArn=fake_arn)
    )
    assert code == "TrustStoreNotFound", (
        f"expected TrustStoreNotFoundException for fabricated ARN {fake_arn!r}, got {code!r}"
    )
    expected_message = f"Trust store ARN '{fake_arn}' not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====
def _error(fn):
    """Return (code, message) of the ClientError fn raises; raise AssertionError if it succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


def _fake_trust_store_arn(ctx):
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    rand = ctx.unique_name("nonexistent-ts").replace("sim2real-", "").replace("_", "-")
    return f"arn:aws:elasticloadbalancing:{ctx.region}:{account}:truststore/{rand}/0123456789abcdef"


def _generate_ca_pem():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-elbv2-ca")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _create_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-elbv2-ts-").lower().replace("_", "-").rstrip("-")
    region = ctx.region
    if region == "us-east-1":  # S3 CreateBucket rejects an explicit LocationConstraint here
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


def _delete_trust_store_safe(elbv2, ts_arn: str, attempts: int = 12, delay: float = 5.0) -> None:
    for _ in range(attempts):
        try:
            elbv2.delete_trust_store(TrustStoreArn=ts_arn)
            return
        except elbv2.exceptions.TrustStoreNotFoundException:
            return
        except elbv2.exceptions.TrustStoreInUseException:
            time.sleep(delay)


def _wait_trust_store_status(elbv2, ts_arn: str, want: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]["Status"]
        if status == want:
            return
        time.sleep(5)
    raise AssertionError(f"trust store never reached status={want}, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
