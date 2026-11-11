"""trust-store-revocation-add-describe-remove-roundtrip."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trust-store-revocation-add-describe-remove-roundtrip"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A revocation added via AddTrustStoreRevocations appears in DescribeTrustStoreRevocations and disappears after removal."""
    elbv2 = ctx.client("elbv2")
    bucket = _create_bucket(ctx)
    ca_pem, ca_key, ca_cert = _self_signed_ca(ctx.unique_name("elbv2-ca-"))
    _put_object(ctx, bucket, "ca-bundle.pem", ca_pem)

    ts_arn = elbv2.create_trust_store(
        Name=_ts_name(ctx), CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key="ca-bundle.pem"
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))
    _wait_for_trust_store_status(ctx, ts_arn, "ACTIVE")

    revoked_serial = 424242
    crl_pem = _self_signed_crl_pem(ca_cert, ca_key, revoked_serials=[revoked_serial])
    _put_object(ctx, bucket, "revoked.crl.pem", crl_pem)

    added = elbv2.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"RevocationType": "CRL", "S3Bucket": bucket, "S3Key": "revoked.crl.pem"}],
    )["TrustStoreRevocations"]
    assert len(added) == 1, f"AddTrustStoreRevocations returned {len(added)} entries, expected 1"
    revocation_id = added[0]["RevocationId"]
    assert added[0]["TrustStoreArn"] == ts_arn, f"revocation TrustStoreArn={added[0]['TrustStoreArn']!r}, expected {ts_arn!r}"
    assert added[0]["RevocationType"] == "CRL", f"revocation RevocationType={added[0]['RevocationType']!r}, expected 'CRL'"
    assert added[0]["NumberOfRevokedEntries"] == 1, (
        f"CRL revokes 1 serial ({revoked_serial}) but AddTrustStoreRevocations reported "
        f"NumberOfRevokedEntries={added[0]['NumberOfRevokedEntries']}"
    )

    described = elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"]
    matching = [r for r in described if r["RevocationId"] == revocation_id]
    assert len(matching) == 1, f"expected exactly 1 describe entry for revocation {revocation_id}, found {len(matching)}"
    assert matching[0]["RevocationType"] == "CRL", f"described RevocationType={matching[0]['RevocationType']!r}, expected 'CRL'"
    assert matching[0]["NumberOfRevokedEntries"] == 1, (
        f"described NumberOfRevokedEntries={matching[0]['NumberOfRevokedEntries']}, expected 1"
    )

    elbv2.remove_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[revocation_id])

    after_remove = elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"]
    assert all(
        r["RevocationId"] != revocation_id for r in after_remove
    ), f"revocation {revocation_id} still present in DescribeTrustStoreRevocations after RemoveTrustStoreRevocations"

    by_id_code, by_id_message = _client_error(
        lambda: elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[revocation_id])
    )
    assert by_id_code == "RevocationIdNotFound", (
        f"describe by removed RevocationId={revocation_id!r} returned code={by_id_code!r}, "
        "expected RevocationIdNotFound"
    )
    expected = f"Revocation ID '{revocation_id}' not found"
    assert by_id_message == expected, f"expected message {expected!r}, got {by_id_message!r}"


# ===== helpers =====

def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2ts-").lower()
    if ctx.region == "us-east-1":  # S3 rejects an explicit LocationConstraint for its home region
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


def _self_signed_crl_pem(ca_cert, ca_key, revoked_serials=()) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=365))
    )
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build()
        )
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


def _client_error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError("expected a ClientError but the call succeeded")


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
