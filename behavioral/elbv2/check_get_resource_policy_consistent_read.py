"""get-resource-policy-consistent-read."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "get-resource-policy-consistent-read"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on a new trust store returns the same result on every read for ~3s: the
    same error code and message, or the same policy document, and never neither."""
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-ts"}],
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _delete_trust_store_safe(elbv2, ts_arn))

    first_code, first_message, first_policy = _get_resource_policy(elbv2, ts_arn)

    # Sample for 3s so an answer that changes after some elapsed time is caught; stop on first drift.
    readings = [(first_code, first_message, first_policy), _get_resource_policy(elbv2, ts_arn)]
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        time.sleep(0.5)
        reading = _get_resource_policy(elbv2, ts_arn)
        readings.append(reading)
        if reading != readings[0]:
            break

    for code, message, policy in readings[1:]:
        assert code == first_code, (
            f"error code drifted across reads: {first_code!r} vs {code!r}"
        )
        assert message == first_message, (
            f"error message drifted across reads: {first_message!r} vs {message!r}"
        )
        assert policy == first_policy, (
            f"policy document drifted across reads: {first_policy!r} vs {policy!r}"
        )
    assert first_code is not None or first_policy is not None, (
        "GetResourcePolicy returned neither an error nor a policy document"
    )


# ===== helpers =====

def _generate_ca_pem() -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-elbv2-rp-ca")])
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


def _get_resource_policy(elbv2, resource_arn: str) -> tuple[str | None, str | None, str | None]:
    try:
        resp = elbv2.get_resource_policy(ResourceArn=resource_arn)
        return None, None, resp.get("Policy")
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is None:
            return type(exc).__name__, str(exc), None
        err = response.get("Error", {})
        return err.get("Code"), err.get("Message"), None


def _create_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-elbv2-rp-").lower().replace("_", "-").rstrip("-")
    region = ctx.region
    # S3 rejects an explicit LocationConstraint in us-east-1 and requires one elsewhere.
    if region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-elbv2-rp"}]},
    )
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


