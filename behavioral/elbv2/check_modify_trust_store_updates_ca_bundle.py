"""modify-trust-store-updates-ca-bundle."""
from __future__ import annotations

import datetime
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "modify-trust-store-updates-ca-bundle"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """ModifyTrustStore replaces the CA bundle; the new bundle is byte-identical via GetTrustStoreCaCertificatesBundle."""
    elbv2 = ctx.client("elbv2")
    bucket = _create_bucket(ctx)

    cert1_pem, _k1, _c1 = _self_signed_ca(ctx.unique_name("elbv2-ca1-"))
    _put_object(ctx, bucket, "bundle1.pem", cert1_pem)

    ts_arn = elbv2.create_trust_store(
        Name=_ts_name(ctx),
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="bundle1.pem",
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))
    _wait_for_trust_store_status(ctx, ts_arn, "ACTIVE")

    cert2_pem, _k2, _c2 = _self_signed_ca(ctx.unique_name("elbv2-ca2-"))
    assert cert2_pem != cert1_pem, "two independently generated self-signed CAs must not collide"
    _put_object(ctx, bucket, "bundle2.pem", cert2_pem)

    modified = elbv2.modify_trust_store(
        TrustStoreArn=ts_arn, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key="bundle2.pem"
    )["TrustStores"][0]
    assert modified["TrustStoreArn"] == ts_arn, f"expected ModifyTrustStore to echo {ts_arn}, got {modified['TrustStoreArn']}"

    active = _wait_for_trust_store_status(ctx, ts_arn, "ACTIVE")
    assert active["NumberOfCaCertificates"] == 1, f"expected 1 CA certificate after modify, got {active['NumberOfCaCertificates']}"

    bundle_url = elbv2.get_trust_store_ca_certificates_bundle(TrustStoreArn=ts_arn)["Location"]
    try:
        _url, _route = ctx.endpoint_route(bundle_url)
        with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=30) as resp:
            downloaded = resp.read()
    except urllib.error.URLError as exc:
        raise AssertionError(f"unable to fetch the presigned CA bundle URL from this network: {exc}") from exc

    assert downloaded.strip() == cert2_pem.strip(), (
        f"expected the downloaded bundle to be byte-identical to the newly uploaded cert2 "
        f"({len(cert2_pem.strip())} bytes), got {len(downloaded.strip())} bytes"
    )
    assert downloaded.strip() != cert1_pem.strip(), "downloaded bundle still matches the superseded cert1 — modify did not take effect"


# ===== helpers =====

def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2ts-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})

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
