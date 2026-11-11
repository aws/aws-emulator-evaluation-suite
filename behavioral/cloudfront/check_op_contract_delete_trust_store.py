"""op-contract-deleteTrustStore."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteTrustStore"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTrustStore with a wrong IfMatch is refused with InvalidIfMatchVersion and leaves the
    trust store and its ETag unchanged; with the current ETag it succeeds, after which
    GetTrustStore returns EntityNotFound."""
    cf = ctx.client("cloudfront")

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ts-bkt-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _safe_delete_bucket_and_objects(s3, bucket))

    key = "ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=key, Body=_self_signed_ca_cert_pem().encode("utf-8"))

    name = ctx.unique_name("sim2real-ts-")
    created = cf.create_trust_store(
        Name=name,
        CaCertificatesBundleSource={
            "CaCertificatesBundleS3Location": {
                "Bucket": bucket,
                "Key": key,
                "Region": ctx.region,
            }
        },
    )

    ts_id = created["TrustStore"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete(cf, ts_id))

    _poll_until(
        lambda: cf.get_trust_store(Identifier=ts_id)["TrustStore"]["Status"],
        lambda status: status in ("active", "failed"),
        timeout_s=180.0,
        interval_s=5.0,
    )

    current = cf.get_trust_store(Identifier=ts_id)
    real_etag = current["ETag"]

    # a wrong ETag is rejected: CloudFront reports InvalidIfMatchVersion (not the generic
    # PreconditionFailed) for TrustStore mutations.
    code, message = _error(
        lambda: cf.delete_trust_store(Id=ts_id, IfMatch="E000000000FAKEBOGUS")
    )
    assert code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {code}"
    assert message == "The If-Match version is missing or not valid for the resource.", (
        f"expected the exact refusal message, got {message!r}"
    )

    # The rejected delete must not have applied: the trust store is still there,
    # with the same ETag we already hold.
    still = cf.get_trust_store(Identifier=ts_id)
    assert still["TrustStore"]["Id"] == ts_id
    assert still["ETag"] == real_etag, "a rejected delete must not advance the ETag"

    # success path
    cf.delete_trust_store(Id=ts_id, IfMatch=real_etag)

    code_after, code_after_message = _error(lambda: cf.get_trust_store(Identifier=ts_id))
    assert code_after == "EntityNotFound", f"expected EntityNotFound after delete, got {code_after}"
    assert code_after_message == "The specified trust store does not exist.", (
        f"expected the exact refusal message, got {code_after_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )


def _safe_delete_bucket_and_objects(s3, bucket: str) -> None:
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _safe_delete(cf, ts_id: str) -> None:
    try:
        current = cf.get_trust_store(Identifier=ts_id)
        cf.delete_trust_store(Id=ts_id, IfMatch=current["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


def _self_signed_ca_cert_pem() -> str:
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
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
