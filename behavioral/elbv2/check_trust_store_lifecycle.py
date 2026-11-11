"""trust-store-lifecycle."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from fidelity_tests_runner import require_tools
from behavioral_harness import tags

CHECK = "trust-store-lifecycle"
GROUP = 'trust-store'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrustStore is describable & ACTIVE; DeleteTrustStore then 404s on Describe."""

    elb = ctx.client("elbv2")

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

    def _describe_fails(arn):
        try:
            elb.describe_trust_stores(TrustStoreArns=[arn])
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES
        return False

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    s3 = ctx.client("s3")

    def _create_s3_object(body, key="bundle.pem"):
        bucket = _clamp_name(ctx.unique_name("sim2real-behav-ts-bkt-"), 60).lower()
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
        s3.put_object(Bucket=bucket, Key=key, Body=body)
        return bucket, key

    def _openssl(args, timeout=30):
        import subprocess
        require_tools("openssl")
        subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=timeout)

    def _generate_root_ca(cn="sim2real-behav-ca"):
        import os as _os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            key_path = _os.path.join(d, "ca-key.pem")
            cert_path = _os.path.join(d, "ca-cert.pem")
            _openssl([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-out", cert_path,
                "-days", "365", "-subj", f"/CN={cn}",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            ])
            with open(cert_path) as f:
                cert_pem = f.read()
            with open(key_path) as f:
                key_pem = f.read()
        return cert_pem, key_pem

    def _wait_trust_store_active(arn, timeout_s=60):
        return _poll_until(
            lambda: elb.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0],
            lambda ts: ts["Status"] == "ACTIVE",
            timeout_s=timeout_s, interval_s=2.0,
            description="trust store reaching ACTIVE",
        )

    def _delete_if_present(arn):
        try:
            elb.delete_trust_store(TrustStoreArn=arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TrustStoreNotFound":
                raise

    def _create_trust_store_with_ca(name=None):
        name = _clamp_name(name or ctx.unique_name("sim2real-behav-ts-"))
        ca_cert_pem, ca_key_pem = _generate_root_ca()
        bucket, key = _create_s3_object(ca_cert_pem.encode(), key="ca-bundle.pem")
        resp = _retry_throttled(lambda: elb.create_trust_store(
            Name=name,
            CaCertificatesBundleS3Bucket=bucket,
            CaCertificatesBundleS3Key=key,
            Tags=_tags_kv(),
        ))
        ts = resp["TrustStores"][0]
        arn = ts["TrustStoreArn"]
        ctx.on_cleanup(lambda: _delete_if_present(arn))
        ts = _wait_trust_store_active(arn)
        return ts, ca_cert_pem, ca_key_pem, bucket, key

    ts, _ca_cert, _ca_key, bucket, key = _create_trust_store_with_ca()
    arn = ts["TrustStoreArn"]
    assert ts["Status"] == "ACTIVE", f"expected ACTIVE right after reaching the terminal poll state, got {ts['Status']!r}"
    assert ts["NumberOfCaCertificates"] >= 1, f"expected at least 1 CA certificate from the uploaded bundle, got {ts['NumberOfCaCertificates']!r}"

    described = elb.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]
    assert described["TrustStoreArn"] == arn, f"independent DescribeTrustStores returned a mismatched ARN: expected {arn}, got {described['TrustStoreArn']!r}"
    assert described["Status"] == "ACTIVE", f"independent DescribeTrustStores did not report ACTIVE: got {described['Status']!r}"

    elb.delete_trust_store(TrustStoreArn=arn)
    _poll_until(
        lambda: _describe_fails(arn),
        lambda gone: gone,
        timeout_s=60, interval_s=3,
        description="trust store deleted",
    )
    code, message = _error(lambda: elb.describe_trust_stores(TrustStoreArns=[arn]))
    assert code == "TrustStoreNotFound", f"expected TrustStoreNotFound from an independent Describe after delete, got {code!r}"
    expected_message = f"Trust store ARN '{arn}' not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    mutation_code, mutation_message = _error(lambda: elb.modify_trust_store(
        TrustStoreArn=arn, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key=key,
    ))
    assert mutation_code == "TrustStoreNotFound", (
        f"a mutation (ModifyTrustStore) on the deleted trust store's ARN must also fail with "
        f"TrustStoreNotFound, got {mutation_code!r}"
    )
    expected_mutation = f"Trust store ARN '{arn}' not found"
    assert mutation_message == expected_mutation, (
        f"expected message {expected_mutation!r}, got {mutation_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
