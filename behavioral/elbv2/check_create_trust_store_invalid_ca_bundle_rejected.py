"""create-trust-store-invalid-ca-bundle-rejected."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "create-trust-store-invalid-ca-bundle-rejected"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrustStore with a non-PEM CA bundle fails with InvalidCaCertificatesBundle and the exact message and
    leaves no trust store, while the same request with a valid PEM bundle reaches ACTIVE."""
    elbv2 = ctx.client("elbv2")
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="garbage.pem", Body=b"this is not a certificate bundle\n")

    bad_name = ctx.unique_name("sim2real-behav-")
    code, message = _error(
        lambda: elbv2.create_trust_store(
            Name=bad_name,
            CaCertificatesBundleS3Bucket=bucket,
            CaCertificatesBundleS3Key="garbage.pem",
        )
    )
    assert code == "InvalidCaCertificatesBundle", f"CODE={code!r}"
    assert message == "CA certificate bundle does not contain any certificates", f"MSG={message!r}"

    not_found_code, not_found_message = _error(lambda: elbv2.describe_trust_stores(Names=[bad_name]))
    assert not_found_code == "TrustStoreNotFound", f"CODE={not_found_code!r}"
    assert not_found_message == f"Trust store name '{bad_name}' not found", f"MSG={not_found_message!r}"

    ca_cert_pem = _generate_self_signed_ca_pem()
    s3.put_object(Bucket=bucket, Key="good-ca-bundle.pem", Body=ca_cert_pem)
    good_name = ctx.unique_name("sim2real-behav-")
    good_arn = elbv2.create_trust_store(
        Name=good_name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="good-ca-bundle.pem",
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=good_arn))
    status = _wait_for_terminal_status(elbv2, good_arn)
    assert status == "ACTIVE", f"unexpected terminal status for a valid bundle: {status}"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Run ``fn``, which AWS refuses, and return the refusal's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_terminal_status(elbv2, arn: str, timeout_s: float = 180.0) -> str:
    """Poll DescribeTrustStores until the store leaves CREATING; raise on timeout."""
    import time

    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = elbv2.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]["Status"]
        if status != "CREATING":
            return status
        time.sleep(5)
    raise AssertionError(f"trust store {arn} still {status} after {timeout_s}s")


def _generate_self_signed_ca_pem() -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-behav-ca")])
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


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ts-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=name)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
