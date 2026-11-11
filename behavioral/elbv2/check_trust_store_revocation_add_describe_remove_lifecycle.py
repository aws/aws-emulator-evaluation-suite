"""trust-store-revocation-add-describe-remove-lifecycle."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trust-store-revocation-add-describe-remove-lifecycle"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTrustStoreRevocations entries appear via Describe and are gone after RemoveTrustStoreRevocations."""
    elbv2 = ctx.client("elbv2")

    ca_key, ca_cert = _generate_ca(ctx.unique_name("sim2real-ca-"))
    ts_arn = _create_trust_store(ctx, ca_cert)

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    crl_key = "revoked.crl"
    s3.put_object(Bucket=bucket, Key=crl_key, Body=_crl_pem(ca_key, ca_cert))

    add_resp = elbv2.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"S3Bucket": bucket, "S3Key": crl_key, "RevocationType": "CRL"}],
    )
    revocations = add_resp["TrustStoreRevocations"]
    assert len(revocations) == 1, f"expected exactly one revocation entry, got {revocations}"
    revocation_id = revocations[0]["RevocationId"]
    assert revocations[0]["TrustStoreArn"] == ts_arn, revocations[0]

    described = elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"]
    ids = {r["RevocationId"] for r in described}
    assert revocation_id in ids, f"revocation {revocation_id} missing from describe: {ids}"

    elbv2.remove_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[revocation_id])

    described_after = elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"]
    ids_after = {r["RevocationId"] for r in described_after}
    assert revocation_id not in ids_after, "revocation still listed after RemoveTrustStoreRevocations"

    describe_code, describe_message = _expect_error(
        lambda: elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[revocation_id])
    )
    assert describe_code == "RevocationIdNotFound", (
        f"expected RevocationIdNotFound describing a removed revocation, got {describe_code}"
    )
    expected = f"Revocation ID '{revocation_id}' not found"
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"

    remove_code, remove_message = _expect_error(
        lambda: elbv2.remove_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[revocation_id])
    )
    assert remove_code == "RevocationIdNotFound", (
        f"expected re-removing an already-removed revocation to fail with RevocationIdNotFound, got {remove_code}"
    )
    expected = f"Revocation ID '{revocation_id}' not found"
    assert remove_message == expected, f"expected message {expected!r}, got {remove_message!r}"


# ===== helpers =====
def _expect_error(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError("expected a ClientError but the call succeeded")


def _generate_ca(cn: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _crl_pem(ca_key, ca_cert, revoked_serials=()) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
    )
    for serial in revoked_serials:
        revoked = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build()
        builder = builder.add_revoked_certificate(revoked)
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-elbv2-ts-")
    if ctx.region == "us-east-1":
        # us-east-1 is S3's default region: CreateBucketConfiguration must be omitted there
        # or the call fails with InvalidLocationConstraint. Not a resource placement choice.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_object_versions(Bucket=bucket)
    objects = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
    objects += [
        {"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])
    ]
    if objects:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_trust_store(ctx, ca_cert) -> str:
    from cryptography.hazmat.primitives import serialization

    cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    bucket = _create_bucket(ctx)
    ctx.client("s3").put_object(Bucket=bucket, Key="ca-bundle.pem", Body=cert_pem)
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-ts-")
    resp = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ts_arn = resp["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn)))
    _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0],
        lambda d: d["Status"] == "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    return ts_arn


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _safe_call(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrustStoreNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
