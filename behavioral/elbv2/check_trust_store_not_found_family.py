"""trust-store-not-found-family."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trust-store-not-found-family"
GROUP = 'overly-permissive'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Three trust-store ops raise TrustStoreNotFound with the exact message for a fabricated ARN.
    On a real ACTIVE trust store the same calls succeed or fail on the revocation id instead.
    """
    elb = ctx.client("elbv2")
    s3 = ctx.client("s3")

    missing = _fake_trust_store_arn(ctx)
    bucket, key = _create_ca_bundle_object(ctx, s3, "sim2real-behav-negctl-1")

    code, message = _client_error(lambda: elb.modify_trust_store(
        TrustStoreArn=missing, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key=key,
    ))
    assert code == "TrustStoreNotFound", f"expected TrustStoreNotFound modifying a fabricated trust store, got {code!r}"
    expected = f"Trust store ARN '{missing}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _client_error(lambda: elb.get_trust_store_ca_certificates_bundle(TrustStoreArn=missing))
    assert code == "TrustStoreNotFound", f"expected TrustStoreNotFound reading the CA bundle of a fabricated trust store, got {code!r}"
    expected = f"Trust store ARN '{missing}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _client_error(lambda: elb.get_trust_store_revocation_content(TrustStoreArn=missing, RevocationId=1))
    assert code == "TrustStoreNotFound", f"expected TrustStoreNotFound reading revocation content of a fabricated trust store, got {code!r}"
    expected = f"Trust store ARN '{missing}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: proves the refusals above are about the fabricated ARN, not every call.
    real_arn = _create_active_trust_store(ctx, elb, bucket, key)

    bucket2, key2 = _create_ca_bundle_object(ctx, s3, "sim2real-behav-negctl-2")
    modify_resp = _retry_bundle_propagation(
        lambda: elb.modify_trust_store(
            TrustStoreArn=real_arn, CaCertificatesBundleS3Bucket=bucket2, CaCertificatesBundleS3Key=key2,
        )
    )
    assert modify_resp["TrustStores"][0]["TrustStoreArn"] == real_arn, "ModifyTrustStore on a real trust store must succeed"

    location = elb.get_trust_store_ca_certificates_bundle(TrustStoreArn=real_arn).get("Location")
    assert location, "GetTrustStoreCaCertificatesBundle on a real trust store must return a Location"

    code, message = _client_error(lambda: elb.get_trust_store_revocation_content(TrustStoreArn=real_arn, RevocationId=1))
    assert code == "RevocationIdNotFound", (
        "a real trust store with no revocations must fail GetTrustStoreRevocationContent on the "
        f"*revocation id*, not TrustStoreNotFound; got {code!r}"
    )
    expected = "Revocation ID '1' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn() and return (Error.Code, Error.Message), retrying only on throttling.

    An unexpected success raises, so acceptance is never reported as a code mismatch.
    """
    delays = [3, 6, 12, 24, 30]
    for attempt in range(len(delays)):
        try:
            result = fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _THROTTLE_CODES:
                return code, exc.response.get("Error", {}).get("Message")
            time.sleep(delays[attempt])
            continue
        raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")
    raise AssertionError("exhausted retries while throttled")


def _retry_bundle_propagation(fn, attempts=6, delay_s=5.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "CaCertificatesBundleNotFound":
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _fake_trust_store_arn(ctx):
    account = ctx.client("sts").get_caller_identity()["Account"]
    return (f"arn:aws:elasticloadbalancing:{ctx.region}:{account}:"
            "truststore/sim2real-behav-missing/0000000000000000")


def _create_ca_bundle_object(ctx, s3, common_name):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)

    bucket = ctx.unique_name("sim2real-behav-ts-bkt-").lower().replace("_", "-").rstrip("-")
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)

    def _cleanup_bucket(b=bucket):
        try:
            objs = s3.list_objects_v2(Bucket=b).get("Contents", [])
            for o in objs:
                s3.delete_object(Bucket=b, Key=o["Key"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        s3.delete_bucket(Bucket=b)

    ctx.on_cleanup(_cleanup_bucket)
    key_name = "ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=key_name, Body=pem)
    return bucket, key_name


def _create_active_trust_store(ctx, elb, bucket, key, timeout_s=120):
    name = ctx.unique_name("sim2real-behav-ts-")[:32].rstrip("-")
    resp = elb.create_trust_store(
        Name=name, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key=key,
    )
    arn = resp["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: elb.delete_trust_store(TrustStoreArn=arn))

    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = elb.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]["Status"]
        if status == "ACTIVE":
            return arn
        time.sleep(5)
    raise AssertionError(f"trust store did not reach ACTIVE within {timeout_s}s, last status={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
