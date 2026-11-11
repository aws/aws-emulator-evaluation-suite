"""get-trust-store-ca-bundle-returns-full-uploaded-bundle."""
from __future__ import annotations

import datetime
import time
import urllib.request

from behavioral_harness import tags

CHECK = "get-trust-store-ca-bundle-returns-full-uploaded-bundle"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetTrustStoreCaCertificatesBundle's Location points at the exact bytes of the CA
    bundle that was uploaded to S3 for the trust store, byte-for-byte."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    ca_pem = _make_ca_bundle(x509, hashes, rsa, NameOID, serialization)
    bucket, key_name = _upload_bundle(ctx, ca_pem)

    elbv2 = ctx.client("elbv2")
    ts_name = ctx.unique_name("sim2real-ts-")[:32].rstrip("-")
    ts = elbv2.create_trust_store(
        Name=ts_name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key=key_name,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TrustStores"][0]
    ts_arn = ts["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))
    _wait_trust_store_active(ctx, ts_arn)

    location = elbv2.get_trust_store_ca_certificates_bundle(TrustStoreArn=ts_arn)["Location"]
    _url, _route = ctx.endpoint_route(location)
    with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=30) as resp:  # noqa: S310
        downloaded = resp.read()

    assert downloaded == ca_pem, (
        f"downloaded CA bundle ({len(downloaded)} bytes) does not match the uploaded bundle "
        f"({len(ca_pem)} bytes)"
    )


# ===== helpers =====


def _make_ca_bundle(x509, hashes, rsa, NameOID, serialization) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-elbv2-cabundle-ca")])
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
    bucket = ctx.unique_name("sim2real-elbv2-cab-").lower().replace("_", "-")
    kwargs: dict = {"Bucket": bucket}
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})

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
