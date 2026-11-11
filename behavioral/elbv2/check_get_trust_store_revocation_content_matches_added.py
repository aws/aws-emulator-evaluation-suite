"""get-trust-store-revocation-content-matches-added."""
from __future__ import annotations

import datetime
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "get-trust-store-revocation-content-matches-added"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetTrustStoreRevocationContent returns the exact bytes previously submitted via AddTrustStoreRevocations."""
    elbv2 = ctx.client("elbv2")
    bucket = _create_bucket(ctx)
    ca_pem, ca_key, ca_cert = _self_signed_ca(ctx.unique_name("elbv2-ca-"))
    _put_object(ctx, bucket, "ca-bundle.pem", ca_pem)

    ts_arn = elbv2.create_trust_store(
        Name=_ts_name(ctx),
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))
    _wait_for_trust_store_status(ctx, ts_arn, "ACTIVE")

    crl_pem = _self_signed_crl_pem(ca_cert, ca_key)
    _put_object(ctx, bucket, "content.crl.pem", crl_pem)

    revocation_id = elbv2.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"RevocationType": "CRL", "S3Bucket": bucket, "S3Key": "content.crl.pem"}],
    )["TrustStoreRevocations"][0]["RevocationId"]

    location = elbv2.get_trust_store_revocation_content(
        TrustStoreArn=ts_arn, RevocationId=revocation_id
    )["Location"]
    try:
        _url, _route = ctx.endpoint_route(location)
        with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=30) as resp:
            downloaded = resp.read()
    except urllib.error.URLError as exc:
        raise AssertionError(f"unable to fetch the presigned revocation content URL: {exc}") from exc

    assert downloaded.strip() == crl_pem.strip(), (
        f"downloaded revocation content ({len(downloaded)} bytes) does not match the CRL "
        f"submitted via AddTrustStoreRevocations ({len(crl_pem)} bytes)"
    )

    # a bogus revocation id on the same trust store is rejected distinctly
    from botocore.exceptions import ClientError

    try:
        elbv2.get_trust_store_revocation_content(TrustStoreArn=ts_arn, RevocationId=999999999)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "RevocationIdNotFound", f"expected RevocationIdNotFound, got {code!r}"
        expected_message = "Revocation ID '999999999' not found"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    else:
        raise AssertionError("expected RevocationIdNotFound for an unknown revocation id")


# ===== helpers =====

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


def _self_signed_crl_pem(ca_cert, ca_key) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=365))
    )
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


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
