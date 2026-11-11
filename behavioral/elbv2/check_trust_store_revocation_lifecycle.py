"""trust-store-revocation-lifecycle."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from fidelity_tests_runner import require_tools
from behavioral_harness import tags

CHECK = "trust-store-revocation-lifecycle"
GROUP = 'trust-store'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTrustStoreRevocations creates an entry visible via Describe; RemoveTrustStoreRevocations deletes it again."""

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

    def _client_error(fn):
        """(Code, Message) of the ClientError fn raises, retrying only on throttling; a success raises."""
        delays = [3, 6, 12, 24, 30]
        for attempt in range(5):
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

    def _generate_crl_pem(ca_cert_pem, ca_key_pem):
        import os as _os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ca_crt = _os.path.join(d, "ca.crt")
            ca_key = _os.path.join(d, "ca.key")
            with open(ca_crt, "w") as f:
                f.write(ca_cert_pem)
            with open(ca_key, "w") as f:
                f.write(ca_key_pem)
            _os.makedirs(_os.path.join(d, "newcerts"), exist_ok=True)
            open(_os.path.join(d, "index.txt"), "w").close()
            with open(_os.path.join(d, "crlnumber"), "w") as f:
                f.write("1000")
            conf_path = _os.path.join(d, "openssl.cnf")
            with open(conf_path, "w") as f:
                f.write(
                    "[ca]\ndefault_ca = CA_default\n\n"
                    "[CA_default]\n"
                    f"dir = {d}\n"
                    f"database = {d}/index.txt\n"
                    f"new_certs_dir = {d}/newcerts\n"
                    f"crlnumber = {d}/crlnumber\n"
                    f"certificate = {ca_crt}\n"
                    f"private_key = {ca_key}\n"
                    "default_md = sha256\n"
                    "default_crl_days = 30\n"
                    "policy = policy_any\n\n"
                    "[policy_any]\n"
                    "commonName = supplied\n"
                )
            crl_path = _os.path.join(d, "ca.crl")
            _openssl(["ca", "-gencrl", "-config", conf_path, "-out", crl_path])
            with open(crl_path) as f:
                return f.read()

    def _wait_trust_store_active(arn, timeout_s=60):
        return _poll_until(
            lambda: elb.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0],
            lambda ts: ts["Status"] == "ACTIVE",
            timeout_s=timeout_s, interval_s=2.0,
            description="trust store reaching ACTIVE",
        )

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
        ctx.on_cleanup(lambda: elb.delete_trust_store(TrustStoreArn=arn))
        ts = _wait_trust_store_active(arn)
        return ts, ca_cert_pem, ca_key_pem

    ts, ca_cert_pem, ca_key_pem = _create_trust_store_with_ca()
    ts_arn = ts["TrustStoreArn"]

    crl_pem = _generate_crl_pem(ca_cert_pem, ca_key_pem)
    bucket, key = _create_s3_object(crl_pem.encode(), key="revocation.pem")

    added = elb.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"S3Bucket": bucket, "S3Key": key, "RevocationType": "CRL"}],
    )["TrustStoreRevocations"][0]
    revocation_id = added["RevocationId"]
    assert added["RevocationType"] == "CRL", added
    assert added["NumberOfRevokedEntries"] == 0, added  # our CRL revokes no serials

    revocations = _poll_until(
        lambda: elb.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"],
        lambda rs: any(r["RevocationId"] == revocation_id for r in rs),
        timeout_s=30, interval_s=2.0, description="revocation entry visible",
    )
    assert any(r["RevocationId"] == revocation_id for r in revocations)

    elb.remove_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[revocation_id])

    remaining = _poll_until(
        lambda: elb.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"],
        lambda rs: not any(r["RevocationId"] == revocation_id for r in rs),
        timeout_s=30, interval_s=2.0, description="revocation entry removed",
    )
    assert not any(r["RevocationId"] == revocation_id for r in remaining)

    code, message = _client_error(
        lambda: elb.describe_trust_store_revocations(TrustStoreArn=ts_arn, RevocationIds=[revocation_id])
    )
    assert code == "RevocationIdNotFound", f"describing the removed revocation id: expected RevocationIdNotFound, got {code!r}"
    expected = f"Revocation ID '{revocation_id}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
