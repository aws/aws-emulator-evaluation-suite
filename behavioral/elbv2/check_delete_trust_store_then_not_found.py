"""delete-trust-store-then-not-found."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-trust-store-then-not-found"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteTrustStore, a subsequent DescribeTrustStores for that ARN raises TrustStoreNotFound,
    a mutation on the same dead ARN also raises it, and the freed Name can be reused."""
    elbv2 = ctx.client("elbv2")
    bucket = _create_bucket(ctx)
    name = _ts_name(ctx)
    cert_pem, _key, _cert = _self_signed_ca(ctx.unique_name("elbv2-ca-"))
    _put_object(ctx, bucket, "ca-bundle.pem", cert_pem)

    ts_arn = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TrustStores"][0]["TrustStoreArn"]
    _wait_for_trust_store_status(ctx, ts_arn, "ACTIVE")

    # positive control: the trust store is describable while it exists
    before = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"]
    assert len(before) == 1 and before[0]["TrustStoreArn"] == ts_arn, (
        f"expected exactly one described trust store matching {ts_arn}, got {before!r}"
    )

    elbv2.delete_trust_store(TrustStoreArn=ts_arn)

    code, message = _error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]))
    assert code == "TrustStoreNotFound", f"expected TrustStoreNotFound describing a deleted trust store, got {code}"
    assert message == f"Trust store ARN '{ts_arn}' not found", f"describe_trust_stores MESSAGE={message!r}"

    # the deletion also took effect for tag lookups on the same ARN
    tag_code, tag_message = _error(lambda: elbv2.describe_tags(ResourceArns=[ts_arn]))
    assert tag_code == "TrustStoreNotFound", f"expected TrustStoreNotFound tagging a deleted trust store, got {tag_code}"
    assert tag_message == "One or more trust stores not found", f"describe_tags MESSAGE={tag_message!r}"

    # the dead ARN is unusable, not just unreadable: a mutation against it fails the same way
    modify_code, modify_message = _error(
        lambda: elbv2.modify_trust_store(
            TrustStoreArn=ts_arn, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key="ca-bundle.pem"
        )
    )
    assert modify_code == "TrustStoreNotFound", (
        f"expected TrustStoreNotFound modifying a deleted trust store, got {modify_code}"
    )
    assert modify_message == f"Trust store ARN '{ts_arn}' not found", f"modify_trust_store MESSAGE={modify_message!r}"

    # the freed Name is reusable once the original trust store is gone
    ts_arn2 = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _safe_delete(elbv2, ts_arn2))
    assert ts_arn2 != ts_arn, f"recreating {name!r} after delete must mint a new ARN, got the same one back"
    reused = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn2])["TrustStores"]
    assert len(reused) == 1 and reused[0]["Name"] == name, (
        f"expected the reused name {name!r} to describe as a fresh, live trust store, got {reused!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2ts-").lower()
    if ctx.region == "us-east-1":  # S3 CreateBucket quirk: LocationConstraint is rejected for us-east-1 itself
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _put_object(ctx, bucket: str, key: str, body: bytes) -> None:
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=body)


def _ts_name(ctx) -> str:
    return ctx.unique_name("ts-")[:32].rstrip("-")


def _self_signed_ca(common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem, key, cert


def _wait_for_trust_store_status(ctx, arn: str, target_status: str, timeout_s: float = 150.0, interval_s: float = 3.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        ts = elbv2.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]
        last = ts["Status"]
        if last == target_status:
            return ts
        time.sleep(interval_s)
    raise AssertionError(f"trust store {arn} did not reach {target_status} within {timeout_s}s (last={last})")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete(elbv2, arn: str) -> None:
    try:
        elbv2.delete_trust_store(TrustStoreArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrustStoreNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
