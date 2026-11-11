"""trust-store-creation-state-transition."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time

from fidelity_tests_runner import require_tools
from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trust-store-creation-state-transition"
GROUP = "state"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrustStore with a valid CA bundle in S3 transitions the trust store from CREATING to
    ACTIVE with the correct certificate count."""
    cert_pem, _key_pem = _generate_self_signed_pem(ctx)

    s3 = ctx.client("s3")
    elbv2 = ctx.client("elbv2")
    bucket = _create_bucket(ctx)
    key = "sim2real-elbv2-ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=key, Body=cert_pem)
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_object(Bucket=bucket, Key=key)))

    name = ctx.unique_name("sim2real-elbv2-ts-")
    resp = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key=key,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ts = resp["TrustStores"][0]
    arn = ts["TrustStoreArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_trust_store(TrustStoreArn=arn)))

    assert ts["Status"] in ("CREATING", "ACTIVE"), ts
    assert ts["Name"] == name, ts

    final_status = _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]["Status"],
        lambda status: status in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert final_status == "ACTIVE", f"trust store never became ACTIVE: {final_status}"

    described = elbv2.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]
    assert described["NumberOfCaCertificates"] == 1, (
        f"uploaded exactly one CA certificate, expected NumberOfCaCertificates == 1: {described}"
    )


# ===== helpers =====
def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "TrustStoreNotFound"):
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _generate_self_signed_pem(ctx):
    tmpdir = tempfile.mkdtemp(prefix="sim2real-elbv2-cert-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmpdir, ignore_errors=True))
    key_path = os.path.join(tmpdir, "key.pem")
    cert_path = os.path.join(tmpdir, "cert.pem")
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path,
        "-out", cert_path, "-days", "2", "-nodes", "-subj", "/CN=sim2real.example.com",
    ]
    require_tools("openssl")
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=30)
    except subprocess.CalledProcessError as e:
        raise AssertionError(f"openssl failed to generate a self-signed cert: {e.stderr!r}")
    with open(cert_path, "rb") as f:
        cert_pem = f.read()
    with open(key_path, "rb") as f:
        key_pem = f.read()
    return cert_pem, key_pem


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-elbv2-ts-").lower().replace("_", "-")
    # us-east-1 is S3's own default region and rejects an explicit LocationConstraint for it.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral"}]})
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_bucket(Bucket=name)))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
