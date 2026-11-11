"""get-trust-store-revocation-content-returns-full-crl-bytes."""
from __future__ import annotations

import datetime
import time
import urllib.request

from behavioral_harness import tags

CHECK = "get-trust-store-revocation-content-returns-full-crl-bytes"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetTrustStoreRevocationContent's Location points at the exact CRL bytes that were
    added via AddTrustStoreRevocations for a specific RevocationId."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    ca_key, ca_cert, ca_pem = _make_ca(x509, hashes, rsa, NameOID, serialization)
    bucket = _create_bucket(ctx)
    ca_key_name = "ca-bundle.pem"
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

    crl_pem = _make_crl(x509, hashes, serialization, ca_key, ca_cert, revoked_serial=424242)
    crl_key_name = "revocation.pem"
    _put(ctx, bucket, crl_key_name, crl_pem)

    add_resp = _add_revocation_with_retry(elbv2, ts_arn, bucket, crl_key_name, attempts=6, delay_s=5.0)
    revocation_id = add_resp["TrustStoreRevocations"][0]["RevocationId"]

    location = elbv2.get_trust_store_revocation_content(
        TrustStoreArn=ts_arn, RevocationId=revocation_id
    )["Location"]
    _url, _route = ctx.endpoint_route(location)
    with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=30) as resp:  # noqa: S310
        downloaded = resp.read()

    assert downloaded == crl_pem, (
        f"downloaded revocation content ({len(downloaded)} bytes) does not match the uploaded "
        f"CRL ({len(crl_pem)} bytes)"
    )


# ===== helpers =====


def _make_ca(x509, hashes, rsa, NameOID, serialization):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-elbv2-revocation-ca")])
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
    return key, cert, cert.public_bytes(serialization.Encoding.PEM)


def _add_revocation_with_retry(elbv2, ts_arn, bucket, key_name, attempts: int, delay_s: float):
    """AddTrustStoreRevocations can transiently report RevocationContentNotFound for a
    just-written S3 object (read-after-write propagation); retry a bounded number of times
    before giving up."""
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(attempts):
        try:
            return elbv2.add_trust_store_revocations(
                TrustStoreArn=ts_arn,
                RevocationContents=[{"S3Bucket": bucket, "S3Key": key_name, "RevocationType": "CRL"}],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RevocationContentNotFound":
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _make_crl(x509, hashes, serialization, ca_key, ca_cert, revoked_serial: int) -> bytes:
    now = datetime.datetime.utcnow()
    revoked = (
        x509.RevokedCertificateBuilder().serial_number(revoked_serial).revocation_date(now).build()
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
        .add_revoked_certificate(revoked)
        .sign(ca_key, hashes.SHA256())
    )
    return crl.public_bytes(serialization.Encoding.PEM)


def _upload(ctx, key_name: str, content: bytes) -> tuple[str, str]:
    bucket = _create_bucket(ctx)
    _put(ctx, bucket, key_name, content)
    return bucket, key_name


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2-rev-").lower().replace("_", "-")
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
