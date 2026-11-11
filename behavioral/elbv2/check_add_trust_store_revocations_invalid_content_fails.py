"""add-trust-store-revocations-invalid-content-fails."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "add-trust-store-revocations-invalid-content-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddTrustStoreRevocations with malformed CRL content fails with InvalidRevocationContent and adds
    nothing, while a well-formed CRL signed by the trust store's own CA is then accepted."""
    elbv2 = ctx.client("elbv2")

    ts_arn, ca_key, ca_cert = _create_trust_store(ctx, ctx.unique_name("sim2real-ca-"))

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    bad_key = "not-a-crl.txt"
    s3.put_object(Bucket=bucket, Key=bad_key, Body=b"this is definitely not a valid X.509 CRL")

    code, message = _error_code(
        lambda: elbv2.add_trust_store_revocations(
            TrustStoreArn=ts_arn,
            RevocationContents=[{"S3Bucket": bucket, "S3Key": bad_key, "RevocationType": "CRL"}],
        )
    )
    # Real AWS raises this error as "InvalidRevocationContent" (no "Exception" suffix on the wire code).
    assert code == "InvalidRevocationContent", f"expected InvalidRevocationContent, got {code}"
    expected_message = "Provided revocation file is not in the correct format"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    revocations = elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"]
    assert revocations == [], f"malformed revocation should not have been added: {revocations}"

    # Positive control: a genuinely valid CRL signed by this trust store's own CA is accepted on
    # the identical trust store, ruling out "AddTrustStoreRevocations rejects every call here".
    crl_key = "valid.crl.pem"
    s3.put_object(Bucket=bucket, Key=crl_key, Body=_build_crl_pem(ca_key, ca_cert, revoked_serial=4242))
    added = elbv2.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"S3Bucket": bucket, "S3Key": crl_key, "RevocationType": "CRL"}],
    )["TrustStoreRevocations"]
    assert len(added) == 1, f"expected exactly one revocation entry created, got {added}"
    revocation_id = added[0]["RevocationId"]

    revocations_after = _poll_until(
        lambda: elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"],
        lambda rs: any(r["RevocationId"] == revocation_id for r in rs),
        timeout_s=60,
        interval_s=3,
    )
    assert any(r["RevocationId"] == revocation_id for r in revocations_after), (
        f"valid CRL revocation {revocation_id} not visible via independent read: {revocations_after}"
    )


def _error_code(fn):
    """Return (code, message) of the ClientError ``fn`` raises; raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _safe_call(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrustStoreNotFound":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _self_signed_cert(cn: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
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


def _build_crl_pem(ca_key, ca_cert, revoked_serial: int) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    now = datetime.datetime.utcnow()
    revoked = x509.RevokedCertificateBuilder().serial_number(revoked_serial).revocation_date(now).build()
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=365))
        .add_revoked_certificate(revoked)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    return crl.public_bytes(serialization.Encoding.PEM)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-elbv2-ts-")
    if ctx.region == "us-east-1":
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


def _create_trust_store(ctx, cn: str):
    cert_pem, ca_key, ca_cert = _self_signed_cert(cn)
    bucket = _create_bucket(ctx)
    ctx.client("s3").put_object(Bucket=bucket, Key="ca-bundle.pem", Body=cert_pem)
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-ts-")
    resp = elbv2.create_trust_store(
        Name=name, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key="ca-bundle.pem"
    )
    ts_arn = resp["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn)))
    _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0],
        lambda d: d["Status"] == "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    return ts_arn, ca_key, ca_cert


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
