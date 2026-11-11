"""create-trust-store-reaches-active."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "create-trust-store-reaches-active"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new trust store reaches ACTIVE with one CA certificate and is returned by DescribeTrustStores; once
    deleted, DescribeTrustStores and a further mutation fail with TrustStoreNotFound and the exact message."""
    elbv2 = ctx.client("elbv2")
    bucket = _create_bucket(ctx)
    cert_pem, _key, _cert = _self_signed_ca(ctx.unique_name("elbv2-ca-"))
    _put_object(ctx, bucket, "ca-bundle.pem", cert_pem)

    name = _ts_name(ctx)
    created = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=_tags_kv(),
    )["TrustStores"][0]
    ts_arn = created["TrustStoreArn"]
    ctx.on_cleanup(lambda: _safe_delete_trust_store(elbv2, ts_arn))

    assert created["Status"] in ("CREATING", "ACTIVE"), created["Status"]
    assert created["Name"] == name

    active = _wait_for_trust_store_status(ctx, ts_arn, "ACTIVE")
    assert active["NumberOfCaCertificates"] == 1

    described = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"]
    assert len(described) == 1
    assert described[0]["TrustStoreArn"] == ts_arn
    assert described[0]["Status"] == "ACTIVE"
    assert described[0]["Name"] == name

    elbv2.delete_trust_store(TrustStoreArn=ts_arn)

    code, message = _error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]))
    assert code == "TrustStoreNotFound", f"expected TrustStoreNotFound after delete, got {code}"
    assert message == f"Trust store ARN '{ts_arn}' not found", f"MSG={message!r}"

    delete_code, delete_message = _error(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))
    assert delete_code == "TrustStoreNotFound", (
        f"expected a second delete on the same ARN to 404 with TrustStoreNotFound, got {delete_code}"
    )
    assert delete_message == f"Trust store ARN '{ts_arn}' not found", f"MSG={delete_message!r}"


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Run ``fn``, which AWS refuses, and return the refusal's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_trust_store(elbv2, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        elbv2.delete_trust_store(TrustStoreArn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "TrustStoreNotFound":
            raise


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2ts-").lower()
    if ctx.region == "us-east-1":
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
