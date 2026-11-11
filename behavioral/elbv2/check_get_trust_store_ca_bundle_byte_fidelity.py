"""get-trust-store-ca-bundle-byte-fidelity."""
from __future__ import annotations

import time
import urllib.request

from behavioral_harness import tags

CHECK = "get-trust-store-ca-bundle-byte-fidelity"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags(
    "axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """CreateTrustStore ingests a CA bundle from S3, and GetTrustStoreCaCertificatesBundle later
    returns a location whose bytes are byte-identical to the original S3 object."""
    pem_bytes, _cert, _key = _generate_ca_bundle()

    s3 = ctx.client("s3")
    elbv2 = ctx.client("elbv2")

    bucket = ctx.unique_name("sim2real-elbv2-ca-")
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}]},
    )

    key = "ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=key, Body=pem_bytes)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    name = _trust_store_name(ctx, "sim2realca")
    created = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key=key,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )["TrustStores"][0]
    arn = created["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=arn))

    _wait_for_trust_store_active(elbv2, arn)

    location = elbv2.get_trust_store_ca_certificates_bundle(TrustStoreArn=arn)["Location"]
    fetched = _fetch_location_bytes(ctx, s3, location)

    assert fetched == pem_bytes, (
        f"fetched CA bundle ({len(fetched)} bytes) is not byte-identical to the uploaded "
        f"source object ({len(pem_bytes)} bytes)"
    )


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


def _trust_store_name(ctx, prefix: str) -> str:
    name = ctx.unique_name(f"{prefix}-")
    return name[:32].rstrip("-")


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


def _fetch_location_bytes(ctx, s3, location: str) -> bytes:
    if location.startswith("s3://"):
        without_scheme = location[len("s3://"):]
        bucket, _, key = without_scheme.partition("/")
        key = key.split("?")[0]
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    _url, _route = ctx.endpoint_route(location)
    with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=30) as resp:
        return resp.read()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
