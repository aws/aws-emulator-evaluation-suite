"""get-resource-policy-no-policy-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-resource-policy-no-policy-rejected"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on a well-formed, own-account trust-store ARN that does not exist raises
    ResourceNotFoundException, while an existing trust store answers it without raising."""
    ca_pem, _cert, _key = _generate_ca_bundle()

    elbv2 = ctx.client("elbv2")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-elbv2-nprej-")
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=key, Body=ca_pem)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    name = ctx.unique_name("sim2realgp-")[:32].rstrip("-")
    ts = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key=key,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TrustStores"][0]
    arn = ts["TrustStoreArn"]
    ctx.on_cleanup(lambda: _delete_trust_store_if_present(elbv2, arn))
    _wait_for_trust_store_active(elbv2, arn)

    # Positive control: GetResourcePolicy on the real, existing trust store must not raise
    # ResourceNotFoundException (whatever policy content it returns for an unshared trust
    # store is out of scope here — the point is the resource itself resolves).
    elbv2.get_resource_policy(ResourceArn=arn)

    # Now delete the trust store and confirm GetResourcePolicy on that now-nonexistent ARN
    # is rejected with ResourceNotFoundException.
    elbv2.delete_trust_store(TrustStoreArn=arn)
    _wait_for_trust_store_gone(elbv2, arn)

    code, message = _error(lambda: elbv2.get_resource_policy(ResourceArn=arn))
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected_message = f"Trust store ARN '{arn}' not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====


def _generate_ca_bundle():
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-behavioral-ca")]
    )
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
    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
    return pem_bytes, cert, key


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )


def _wait_for_trust_store_active(elbv2, arn: str, timeout_s: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        ts = elbv2.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]
        last_status = ts["Status"]
        if last_status == "ACTIVE":
            return
        time.sleep(2.0)
    raise AssertionError(
        f"trust store {arn} never reached ACTIVE status within {timeout_s}s "
        f"(last observed status: {last_status})"
    )


def _wait_for_trust_store_gone(elbv2, arn: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            elbv2.describe_trust_stores(TrustStoreArns=[arn])
        except ClientError as err:
            if err.response["Error"]["Code"] == "TrustStoreNotFound":
                return
            raise
        time.sleep(2.0)
    raise AssertionError(f"trust store {arn} was not deleted within {timeout_s}s")


def _delete_trust_store_if_present(elbv2, arn: str) -> None:
    try:
        elbv2.delete_trust_store(TrustStoreArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "TrustStoreNotFound":
            raise


def _error(fn):
    """Return (code, message) of the ClientError fn raises; raise AssertionError if it succeeds."""
    try:
        resp = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
