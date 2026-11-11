"""trust-store-bucket-not-found-error."""
from __future__ import annotations

import datetime
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trust-store-bucket-not-found-error"
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
    """CreateTrustStore referencing a nonexistent S3 bucket raises CaCertificatesBundleNotFound and
    leaves no trust store behind, while an otherwise-identical request against a real bucket with a
    valid CA bundle succeeds."""

    elb = ctx.client("elbv2")
    s3 = ctx.client("s3")

    def _tags_kv():
        return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    def _error(fn):
        """Call fn(); return its error (code, message). An unexpected SUCCESS raises, so a target
        that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
        delays = [3, 6, 12, 24, 30]
        for attempt in range(5):
            try:
                result = fn()
            except ClientError as exc:
                err = exc.response.get("Error", {})
                if err.get("Code") in _THROTTLE_CODES:
                    time.sleep(delays[attempt])
                    continue
                return err.get("Code"), err.get("Message")
            raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
        raise AssertionError("exhausted retries against throttling")

    def _wait_for_terminal_status(arn, timeout_s=150.0, interval_s=3.0):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = elb.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]["Status"]
            if last in ("ACTIVE", "FAILED"):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"trust store {arn} did not leave CREATING within {timeout_s}s (last={last})")

    def _create_bucket():
        bucket = _clamp_name(ctx.unique_name("sim2real-behav-ts-bkt-"), 60).lower()
        kwargs = {"Bucket": bucket}
        if ctx.region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
        s3.create_bucket(**kwargs)

        def _cleanup():
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)

        ctx.on_cleanup(_cleanup)
        return bucket

    def _self_signed_ca_pem():
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

    # Break: CreateTrustStore points at a bucket that was never created.
    bad_name = _clamp_name(ctx.unique_name("sim2real-behav-ts-"))
    missing_bucket = ctx.unique_name("sim2real-behav-nonexistent-bkt-").lower()
    code, message = _error(
        lambda: elb.create_trust_store(
            Name=bad_name,
            CaCertificatesBundleS3Bucket=missing_bucket,
            CaCertificatesBundleS3Key="bundle.pem",
            Tags=_tags_kv(),
        )
    )
    assert code == "CaCertificatesBundleNotFound", code
    expected_message = "Provided CA certificate bundle was not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect-absent: the failed create left no trust store behind, at an independent read.
    not_found_code, not_found_message = _error(lambda: elb.describe_trust_stores(Names=[bad_name]))
    assert not_found_code == "TrustStoreNotFound", not_found_code
    expected_not_found = f"Trust store name '{bad_name}' not found"
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )

    # Positive control: an otherwise-identical request against a real bucket with a valid
    # CA bundle succeeds, so the rejection above is specific to the missing bucket.
    bucket = _create_bucket()
    s3.put_object(Bucket=bucket, Key="ca-bundle.pem", Body=_self_signed_ca_pem())
    good_name = _clamp_name(ctx.unique_name("sim2real-behav-ts-"))
    good_ts = elb.create_trust_store(
        Name=good_name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=_tags_kv(),
    )["TrustStores"][0]
    ctx.on_cleanup(lambda: elb.delete_trust_store(TrustStoreArn=good_ts["TrustStoreArn"]))
    assert good_ts["Status"] in ("CREATING", "ACTIVE"), good_ts["Status"]
    assert good_ts["Name"] == good_name, f"expected={good_name!r} actual={good_ts['Name']!r}"

    # Wait for the trust store to leave CREATING before the check ends: DeleteTrustStore can
    # reject a request while the CA bundle is still being validated, which would otherwise leak
    # the resource past cleanup's best-effort, silently-swallowed teardown.
    final_status = _wait_for_terminal_status(good_ts["TrustStoreArn"])
    assert final_status == "ACTIVE", final_status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
