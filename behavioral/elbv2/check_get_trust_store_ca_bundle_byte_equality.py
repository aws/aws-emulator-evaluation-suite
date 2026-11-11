"""get-trust-store-ca-bundle-byte-equality."""
from __future__ import annotations

import datetime
import time
import urllib.request

from behavioral_harness import tags

CHECK = "get-trust-store-ca-bundle-byte-equality"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The CA bundle bytes returned by GetTrustStoreCaCertificatesBundle (via its
    pre-signed S3 location) are byte-for-byte identical to the object originally
    uploaded to S3 -- no re-encoding, truncation, or line-ending normalization."""
    elbv2 = ctx.client("elbv2")
    s3 = ctx.client("s3")

    _key, _cert, ca_cert_pem, _key_pem = _generate_ca()

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

    location = elbv2.get_trust_store_ca_certificates_bundle(TrustStoreArn=ts_arn)["Location"]
    fetched = _fetch_location(ctx, location)
    assert fetched == ca_cert_pem, (
        f"fetched CA bundle ({len(fetched)} bytes) does not byte-match the uploaded bundle "
        f"({len(ca_cert_pem)} bytes)"
    )


# ===== helpers =====

def _generate_ca():
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
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key, cert, cert_pem, key_pem


def _create_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-elbv2-cab-").lower().replace("_", "-").rstrip("-")
    region = ctx.region
    # us-east-1 rejects CreateBucketConfiguration entirely -- it is the one region S3 predates.
    if region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


def _fetch_location(ctx, location: str) -> bytes:
    _url, _route = ctx.endpoint_route(location)
    with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=30) as resp:
        return resp.read()


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
