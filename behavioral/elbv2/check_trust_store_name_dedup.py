"""trust-store-name-dedup."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from fidelity_tests_runner import require_tools
from behavioral_harness import tags

CHECK = "trust-store-name-dedup"
GROUP = 'overly-permissive'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_NOT_FOUND_CODE = "TrustStoreNotFound"

def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrustStore with a Name a live trust store holds raises DuplicateTrustStoreName, even with a
    different CA bundle, and leaves the original the only one under that name; after it is deleted
    the identical call succeeds."""

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

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

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

    def _wait_trust_store_gone(name, timeout_s=60):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            try:
                last = elb.describe_trust_stores(Names=[name])["TrustStores"]
                if not last:
                    return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == _NOT_FOUND_CODE:
                    return
                raise
            time.sleep(2.0)
        raise AssertionError(f"trust store {name!r} still visible {timeout_s}s after delete: {last!r}")

    def _create_trust_store(name, ca_cert_pem):
        bucket, key = _create_s3_object(ca_cert_pem.encode(), key="ca-bundle.pem")
        return _retry_throttled(lambda: elb.create_trust_store(
            Name=name,
            CaCertificatesBundleS3Bucket=bucket,
            CaCertificatesBundleS3Key=key,
            Tags=_tags_kv(),
        ))

    def _create_trust_store_with_ca(name):
        ca_cert_pem, ca_key_pem = _generate_root_ca()
        resp = _create_trust_store(name, ca_cert_pem)
        ts = resp["TrustStores"][0]
        arn = ts["TrustStoreArn"]

        def _delete(a=arn):
            try:
                elb.delete_trust_store(TrustStoreArn=a)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != _NOT_FOUND_CODE:
                    raise

        ctx.on_cleanup(_delete)
        ts = _wait_trust_store_active(arn)
        return ts, ca_cert_pem, ca_key_pem, _delete

    name = _clamp_name(ctx.unique_name("sim2real-behav-ts-"))
    ts, _ca_cert, _ca_key, delete_first = _create_trust_store_with_ca(name)
    first_arn = ts["TrustStoreArn"]

    other_ca_cert_pem, _ = _generate_root_ca(cn="sim2real-behav-other-ca")
    other_bucket, other_key = _create_s3_object(other_ca_cert_pem.encode(), key="other-bundle.pem")

    def _create_second():
        return elb.create_trust_store(
            Name=name,
            CaCertificatesBundleS3Bucket=other_bucket,
            CaCertificatesBundleS3Key=other_key,
            Tags=_tags_kv(),
        )

    try:
        leaked = _retry_throttled(_create_second)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "DuplicateTrustStoreName", f"expected DuplicateTrustStoreName, got {code!r}"
        message = exc.response.get("Error", {}).get("Message")
        expected = f"A trust store with the name '{name}' already exists"
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        leaked_ts = leaked["TrustStores"][0]
        leaked_arn = leaked_ts["TrustStoreArn"]
        ctx.on_cleanup(lambda: elb.delete_trust_store(TrustStoreArn=leaked_arn))
        raise AssertionError(
            f"expected DuplicateTrustStoreName, but the second CreateTrustStore SUCCEEDED and "
            f"returned {leaked_ts!r}"
        )

    # effect-absent: an independent read still shows exactly the original trust store under this name
    surviving = elb.describe_trust_stores(Names=[name])["TrustStores"]
    assert [t["TrustStoreArn"] for t in surviving] == [first_arn], (
        f"expected only the original trust store {first_arn!r} under name {name!r}, "
        f"got {surviving!r}"
    )

    # restore: once the name is freed, the identical call succeeds
    delete_first()
    _wait_trust_store_gone(name)

    resp2 = _create_trust_store(name, other_ca_cert_pem)
    ts2 = resp2["TrustStores"][0]
    arn2 = ts2["TrustStoreArn"]
    ctx.on_cleanup(lambda: elb.delete_trust_store(TrustStoreArn=arn2))
    ts2 = _wait_trust_store_active(arn2)
    assert ts2["Name"] == name, f"expected restored trust store named {name!r}, got {ts2['Name']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
