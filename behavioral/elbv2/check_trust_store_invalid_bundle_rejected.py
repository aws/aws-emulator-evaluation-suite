"""trust-store-invalid-bundle-rejected."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trust-store-invalid-bundle-rejected"
GROUP = 'overly-permissive'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})


def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrustStore with a non-PEM CA bundle fails with InvalidCaCertificatesBundle and the exact message and
    leaves no trust store, while the same request with a valid PEM bundle creates one."""

    elb = ctx.client("elbv2")
    s3 = ctx.client("s3")

    def _tags_kv():
        return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    def _retry_throttled(fn, attempts=5):
        delays = [3, 6, 12, 24, 30]
        last_exc = None
        for attempt in range(attempts):
            try:
                return fn()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code not in _THROTTLE_CODES:
                    raise
                last_exc = exc
                time.sleep(delays[min(attempt, len(delays) - 1)])
        raise last_exc

    def _expect_rejected(fn):
        try:
            result = _retry_throttled(fn)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(
            f"expected the call to be rejected, but it succeeded: {result!r}"
        )

    def _assert_trust_store_absent(name):
        try:
            resp = elb.describe_trust_stores(Names=[name])
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            assert code == "TrustStoreNotFound", (
                f"expected TrustStoreNotFound for the rejected trust store {name!r}, got {code!r}"
            )
            message = exc.response.get("Error", {}).get("Message")
            expected_message = f"Trust store name '{name}' not found"
            assert message == expected_message, (
                f"expected message {expected_message!r}, got {message!r}"
            )
            return
        found = resp.get("TrustStores")
        assert not found, (
            f"expected no trust store named {name!r} after a rejected CreateTrustStore call, "
            f"got {found!r}"
        )

    def _create_bucket():
        bucket = _clamp_name(ctx.unique_name("sim2real-behav-ts-"), 60).lower()
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
        return bucket

    def _generate_self_signed_ca_pem() -> bytes:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-behav-ca")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM)

    bucket = _create_bucket()

    bad_key = "bundle.pem"
    s3.put_object(Bucket=bucket, Key=bad_key, Body=b"this is not a valid PEM certificate bundle")

    bad_name = _clamp_name(ctx.unique_name("sim2real-behav-ts-"))
    code, message = _expect_rejected(
        lambda: elb.create_trust_store(
            Name=bad_name,
            CaCertificatesBundleS3Bucket=bucket,
            CaCertificatesBundleS3Key=bad_key,
            Tags=_tags_kv(),
        )
    )
    assert code == "InvalidCaCertificatesBundle", (
        f"expected InvalidCaCertificatesBundle for a malformed CA bundle, got {code!r}"
    )
    expected_message = "CA certificate bundle does not contain any certificates"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    _assert_trust_store_absent(bad_name)

    good_key = "good-ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=good_key, Body=_generate_self_signed_ca_pem())
    good_name = _clamp_name(ctx.unique_name("sim2real-behav-ts-"))
    created = _retry_throttled(
        lambda: elb.create_trust_store(
            Name=good_name,
            CaCertificatesBundleS3Bucket=bucket,
            CaCertificatesBundleS3Key=good_key,
            Tags=_tags_kv(),
        )
    )["TrustStores"][0]
    good_arn = created["TrustStoreArn"]

    def _delete_trust_store(arn=good_arn):
        delays = [1, 2, 4, 8, 15]
        for attempt, delay in enumerate(delays):
            try:
                elb.delete_trust_store(TrustStoreArn=arn)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "TrustStoreNotFound":
                    return
                if attempt == len(delays) - 1:
                    raise
                time.sleep(delay)

    ctx.on_cleanup(_delete_trust_store)
    assert created["Status"] in ("CREATING", "ACTIVE"), (
        f"expected creating a trust store from a valid, reachable CA bundle to succeed, "
        f"got status {created['Status']!r}"
    )

    described = elb.describe_trust_stores(TrustStoreArns=[good_arn])["TrustStores"]
    assert described and described[0]["Name"] == good_name, (
        f"expected the successfully created trust store {good_arn!r} to be visible via an "
        f"independent DescribeTrustStores read, got {described!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
