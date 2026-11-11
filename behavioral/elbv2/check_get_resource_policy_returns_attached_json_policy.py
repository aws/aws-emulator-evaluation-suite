"""get-resource-policy-returns-attached-json-policy."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-resource-policy-returns-attached-json-policy"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on an existing, never-shared trust store returns the JSON policy `{}`,
    stable across calls, while a trust store ARN that was never created fails with ResourceNotFound;
    the boundary is the resource's existence, not whether it was shared."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    elbv2 = ctx.client("elbv2")

    ca_pem = _make_ca_bundle(x509, hashes, rsa, NameOID, serialization)
    bucket, key_name = _upload_bundle(ctx, ca_pem)

    ts_name = ctx.unique_name("sim2real-ts-")[:32].rstrip("-")
    ts = elbv2.create_trust_store(
        Name=ts_name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key=key_name,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )["TrustStores"][0]
    ts_arn = ts["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))
    _wait_trust_store_active(ctx, ts_arn)

    bogus_arn = ts_arn[: ts_arn.rindex("/")] + "/deadbeefdeadbeef"
    bogus_code, bogus_message = _error(lambda: elbv2.get_resource_policy(ResourceArn=bogus_arn))
    assert bogus_code == "ResourceNotFound", f"expected ResourceNotFound for a nonexistent trust store, got {bogus_code}"
    expected_message = f"Trust store ARN '{bogus_arn}' not found"
    assert bogus_message == expected_message, f"expected message {expected_message!r}, got {bogus_message!r}"

    policy_json = elbv2.get_resource_policy(ResourceArn=ts_arn)["Policy"]
    assert isinstance(policy_json, str) and policy_json.strip(), "Policy must be a non-empty string"
    policy = json.loads(policy_json)
    assert policy == {}, f"expected the empty-object default policy `{{}}` for a never-shared trust store, got {policy!r}"
    policy_json_2 = elbv2.get_resource_policy(ResourceArn=ts_arn)["Policy"]
    assert json.loads(policy_json_2) == policy, "GetResourcePolicy must be stable across repeated calls"


# ===== helpers =====


def _error(fn):
    """Return (code, message) of the ClientError fn raises; raise AssertionError if it succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


def _make_ca_bundle(x509, hashes, rsa, NameOID, serialization) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-elbv2-resourcepolicy-ca")])
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


def _upload_bundle(ctx, content: bytes) -> tuple[str, str]:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2-rp-").lower().replace("_", "-")
    kwargs: dict = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}]},
    )

    def _cleanup_bucket() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
    key_name = "ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=key_name, Body=content)
    return bucket, key_name


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

