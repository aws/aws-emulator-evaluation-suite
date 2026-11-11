"""trust-store-create-active-delete-404."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trust-store-create-active-delete-404"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrustStore transitions to ACTIVE; after DeleteTrustStore, describe 404s and a further delete 404s too."""
    elbv2 = ctx.client("elbv2")
    check_tags = [{"Key": "simparity-check", "Value": CHECK}]

    cert_pem = _self_signed_ca_pem(ctx.unique_name("sim2real-ca-"))
    bucket = _create_bucket(ctx)
    key = "ca-bundle.pem"
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=cert_pem)

    name = ctx.unique_name("sim2real-ts-")
    resp = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key=key,
        Tags=check_tags,
    )
    ts = resp["TrustStores"][0]
    ts_arn = ts["TrustStoreArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn)))
    assert ts["Status"] in ("CREATING", "ACTIVE"), f"unexpected status right after create: {ts['Status']}"

    described = _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0],
        lambda d: d["Status"] == "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    assert described["Status"] == "ACTIVE", f"trust store never became ACTIVE: {described}"
    assert described["Name"] == name, f"expected name {name!r}, got {described['Name']!r}"
    assert described["TrustStoreArn"] == ts_arn
    assert described["NumberOfCaCertificates"] == 1, (
        f"expected exactly 1 CA certificate from the single-cert bundle, got {described['NumberOfCaCertificates']}"
    )

    elbv2.delete_trust_store(TrustStoreArn=ts_arn)

    code, message = _error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]))
    # Real AWS raises this error as "TrustStoreNotFound" (no "Exception" suffix on the wire code).
    assert code == "TrustStoreNotFound", f"expected TrustStoreNotFound, got {code}"
    expected_message = f"Trust store ARN '{ts_arn}' not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # a mutation on the dead id also fails, not just the read
    redelete_code, redelete_message = _error(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))
    assert redelete_code == "TrustStoreNotFound", (
        f"expected a second DeleteTrustStore on the deleted arn to also 404, got {redelete_code}"
    )
    expected_redelete = f"Trust store ARN '{ts_arn}' not found"
    assert redelete_message == expected_redelete, (
        f"expected message {expected_redelete!r}, got {redelete_message!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    raise AssertionError(f"condition not observed within {timeout_s}s; last saw {last!r}")


def _self_signed_ca_pem(cn: str) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
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
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-elbv2-ts-")
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; this branches on
    # transport (which region we run in), not an assertion.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
