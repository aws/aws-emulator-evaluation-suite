"""get-resource-policy-returns-matching-policy-document."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags

CHECK = "get-resource-policy-returns-matching-policy-document"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An unshared trust store's GetResourcePolicy returns the same JSON document on repeat
    reads, and a nonexistent trust store ARN is rejected with ResourceNotFound.
    """
    ca_cert_pem = _generate_self_signed_ca_pem()
    bucket = _create_bucket(ctx)
    ctx.client("s3").put_object(Bucket=bucket, Key="ca-bundle.pem", Body=ca_cert_pem)

    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-behav-ts-")
    arn = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=arn))
    _wait_trust_store_active(ctx, arn)

    policy_str_1 = elbv2.get_resource_policy(ResourceArn=arn)["Policy"]
    assert policy_str_1, "expected GetResourcePolicy to return a non-empty Policy string"
    json.loads(policy_str_1)

    # elbv2 has no PutResourcePolicy, so stability across reads is what can be asserted.
    policy_str_2 = elbv2.get_resource_policy(ResourceArn=arn)["Policy"]
    assert policy_str_2 == policy_str_1, (
        f"GetResourcePolicy returned a different document on a repeat call for an unchanged "
        f"resource: {policy_str_1!r} vs {policy_str_2!r}"
    )

    # Assert the exact code: a generic error could be ARN-shape validation, not not-found.
    bogus_arn = arn[:-8] + "0" * 8
    code, message = _error(lambda: elbv2.get_resource_policy(ResourceArn=bogus_arn))
    assert code == "ResourceNotFound", (
        f"expected GetResourcePolicy on a nonexistent trust store to fail with "
        f"ResourceNotFound, got {code!r}"
    )
    expected_message = f"Trust store ARN '{bogus_arn}' not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still_there = elbv2.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]
    assert still_there["TrustStoreArn"] == arn, (
        f"expected describe_trust_stores to still report {arn}, got "
        f"{still_there['TrustStoreArn']!r}"
    )
    assert still_there["Status"] == "ACTIVE", (
        f"expected trust store {arn} to remain ACTIVE after GetResourcePolicy reads, got "
        f"{still_there['Status']!r}"
    )


# ===== helpers =====

def _error(fn):
    """Return (code, message) of the ClientError fn raises; raise AssertionError if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


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


def _wait_trust_store_active(ctx, arn: str, timeout_s: float = 90.0, interval_s: float = 2.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = elbv2.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]["Status"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"trust store {arn} never reached ACTIVE status")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
