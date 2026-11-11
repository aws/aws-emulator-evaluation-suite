"""get-trust-store-revocation-content-byte-fidelity."""
from __future__ import annotations

import time
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-trust-store-revocation-content-byte-fidelity"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """AddTrustStoreRevocations ingests a CRL from S3, and GetTrustStoreRevocationContent later
    returns a location whose bytes are byte-identical to the original uploaded revocation file."""
    ca_pem, ca_cert, ca_key = _generate_ca_bundle()
    crl_pem = _generate_crl(ca_cert, ca_key)

    s3 = ctx.client("s3")
    elbv2 = ctx.client("elbv2")

    bucket = ctx.unique_name("sim2real-elbv2-crl-")
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    ca_key_name = "ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=ca_key_name, Body=ca_pem)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=ca_key_name))

    crl_key_name = "revoked.crl"
    s3.put_object(Bucket=bucket, Key=crl_key_name, Body=crl_pem)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=crl_key_name))

    name = _trust_store_name(ctx, "sim2realcrl")
    created = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key=ca_key_name,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["TrustStores"][0]
    arn = created["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=arn))
    _wait_for_trust_store_active(elbv2, arn)

    added = elbv2.add_trust_store_revocations(
        TrustStoreArn=arn,
        RevocationContents=[
            {"S3Bucket": bucket, "S3Key": crl_key_name, "RevocationType": "CRL"}
        ],
    )["TrustStoreRevocations"][0]
    revocation_id = added["RevocationId"]

    location = _wait_for_revocation_location(elbv2, arn, revocation_id)
    fetched = _fetch_location_bytes(ctx, s3, location)

    assert fetched == crl_pem, (
        f"fetched revocation content ({len(fetched)} bytes) is not byte-identical to the "
        f"uploaded CRL ({len(crl_pem)} bytes)"
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


def _generate_crl(ca_cert, ca_key) -> bytes:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
    )
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


def _trust_store_name(ctx, prefix: str) -> str:
    name = ctx.unique_name(f"{prefix}-")
    return name[:32].rstrip("-")


def _create_bucket(ctx, s3, bucket: str) -> None:
    # CreateBucket rejects an explicit LocationConstraint of us-east-1 itself; every other
    # region requires one. This is an S3 API quirk, not a region pin for this check.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral"}]}
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


def _wait_for_revocation_location(elbv2, arn: str, revocation_id: int, timeout_s: float = 60.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return elbv2.get_trust_store_revocation_content(
                TrustStoreArn=arn, RevocationId=revocation_id
            )["Location"]
        except ClientError as err:
            last_err = err
            time.sleep(2.0)
    raise AssertionError(
        f"revocation {revocation_id} on trust store {arn} never became retrievable "
        f"within {timeout_s}s (last error: {last_err})"
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
