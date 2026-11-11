"""get-trust-store-revocation-content-byte-equality."""
from __future__ import annotations

import datetime
import time
import urllib.request

from behavioral_harness import tags

CHECK = "get-trust-store-revocation-content-byte-equality"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The revocation list content fetched via GetTrustStoreRevocationContent (through
    its pre-signed S3 location) matches exactly the CRL bytes that were uploaded and
    referenced in AddTrustStoreRevocations -- no truncation or re-encoding."""
    elbv2 = ctx.client("elbv2")
    s3 = ctx.client("s3")

    ca_key, ca_cert, ca_cert_pem, _key_pem = _generate_ca()

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

    crl_pem = _generate_crl(ca_key, ca_cert, revoked_serial=98765)
    s3.put_object(Bucket=bucket, Key="revocation.crl", Body=crl_pem)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="revocation.crl"))

    revocation = elbv2.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"S3Bucket": bucket, "S3Key": "revocation.crl", "RevocationType": "CRL"}],
    )["TrustStoreRevocations"][0]
    revocation_id = revocation["RevocationId"]

    location = elbv2.get_trust_store_revocation_content(TrustStoreArn=ts_arn, RevocationId=revocation_id)[
        "Location"
    ]
    fetched = _fetch_location(ctx, location)
    assert fetched == crl_pem, (
        f"fetched revocation content ({len(fetched)} bytes) does not byte-match the "
        f"uploaded CRL ({len(crl_pem)} bytes)"
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


def _generate_crl(ca_key, ca_cert, revoked_serial: int) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    now = datetime.datetime.utcnow()
    builder = x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject)
    builder = builder.last_update(now).next_update(now + datetime.timedelta(days=1))
    revoked = x509.RevokedCertificateBuilder().serial_number(revoked_serial).revocation_date(now).build()
    builder = builder.add_revoked_certificate(revoked)
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


def _create_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-elbv2-rev-").lower().replace("_", "-").rstrip("-")
    region = ctx.region
    if region == "us-east-1":  # S3 rejects an explicit LocationConstraint for its default region
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})
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
