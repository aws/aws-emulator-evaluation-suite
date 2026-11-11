"""modify-trust-store-nonexistent-bundle-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "modify-trust-store-nonexistent-bundle-rejected"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """ModifyTrustStore with a nonexistent CA bundle S3 key fails with CaCertificatesBundleNotFound
    and leaves the store ACTIVE with its original bundle; a real replacement bundle is then accepted
    and the fetched bundle changes to it."""
    import cryptography  # noqa: F401

    elbv2 = ctx.client("elbv2")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    ca1_pem, ca1_cert = _self_signed_ca_cert(ctx, "sim2real-elbv2-modts-ca-1")
    ca2_pem, ca2_cert = _self_signed_ca_cert(ctx, "sim2real-elbv2-modts-ca-2")
    s3.put_object(Bucket=bucket, Key="bundle-1.pem", Body=ca1_pem)
    s3.put_object(Bucket=bucket, Key="bundle-2.pem", Body=ca2_pem)

    name = ctx.unique_name("sim2real-ts-modrej-")[:32]
    ts_arn = _create_trust_store_retrying(ctx, elbv2, name, bucket, "bundle-1.pem")["TrustStoreArn"]

    def _cleanup_ts():
        try:
            elbv2.delete_trust_store(TrustStoreArn=ts_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TrustStoreNotFound":
                raise

    ctx.on_cleanup(_cleanup_ts)

    _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )

    code, message = _error(
        lambda: elbv2.modify_trust_store(
            TrustStoreArn=ts_arn,
            CaCertificatesBundleS3Bucket=bucket,
            CaCertificatesBundleS3Key="does-not-exist.pem",
        )
    )
    assert code == "CaCertificatesBundleNotFound", f"expected CaCertificatesBundleNotFound, got {code}"
    assert message == "Provided CA certificate bundle was not found", f"modify_trust_store MESSAGE={message!r}"

    unchanged = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]
    assert unchanged["Status"] == "ACTIVE"
    assert unchanged["NumberOfCaCertificates"] == 1

    from cryptography import x509

    still_bundle1 = x509.load_pem_x509_certificate(
        _fetch_uri(ctx, elbv2.get_trust_store_ca_certificates_bundle(TrustStoreArn=ts_arn)["Location"])
    )
    assert still_bundle1.subject == ca1_cert.subject
    assert still_bundle1.subject != ca2_cert.subject

    elbv2.modify_trust_store(
        TrustStoreArn=ts_arn, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key="bundle-2.pem"
    )
    _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )
    now_bundle2 = x509.load_pem_x509_certificate(
        _fetch_uri(ctx, elbv2.get_trust_store_ca_certificates_bundle(TrustStoreArn=ts_arn)["Location"])
    )
    assert now_bundle2.subject == ca2_cert.subject
    assert now_bundle2.subject != ca1_cert.subject


# ===== helpers =====


def _create_trust_store_retrying(ctx, elbv2, name: str, bucket: str, key: str) -> dict:
    """CreateTrustStore, retrying TooManyTrustStores for up to 10 minutes, because concurrent
    checks share the quota and free their slots when they finish. Never deletes other stores."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 600.0
    tags = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-ts-modrej"}]
    while True:
        try:
            return elbv2.create_trust_store(
                Name=name, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key=key, Tags=tags
            )["TrustStores"][0]
        except ClientError as err:
            if err.response["Error"]["Code"] != "TooManyTrustStores" or time.monotonic() >= deadline:
                raise
            time.sleep(10)


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2-modrej").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for o in objs:
                s3.delete_object(Bucket=bucket, Key=o["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _self_signed_ca_cert(ctx, common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
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
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem, cert


def _fetch_uri(ctx, uri: str) -> bytes:
    if uri.startswith("s3://"):
        rest = uri[len("s3://") :]
        bucket, _, key = rest.partition("/")
        s3 = ctx.client("s3")
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    import urllib.request

    _url, _route = ctx.endpoint_route(uri)
    with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=30) as resp:  # noqa: S310
        return resp.read()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
