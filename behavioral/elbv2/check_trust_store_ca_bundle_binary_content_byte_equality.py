"""trust-store-ca-bundle-binary-content-byte-equality."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import urllib.request

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "trust-store-ca-bundle-binary-content-byte-equality"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetTrustStoreCaCertificatesBundle returns the CA bundle uploaded to S3 for CreateTrustStore byte for byte."""
    require_tools("openssl")

    s3 = ctx.client("s3")
    elbv2 = ctx.client("elbv2")

    bucket = _short_name(ctx, "elbv2tsbkt").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    ca_bundle_bytes = _generate_self_signed_ca_pem()
    key = "ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=key, Body=ca_bundle_bytes)

    ts_name = _short_name(ctx, "ts")
    trust_store = elbv2.create_trust_store(
        Name=ts_name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key=key,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TrustStores"][0]
    ts_arn = trust_store["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))

    _wait_for_trust_store_active(elbv2, ts_arn, timeout_s=60)

    location = elbv2.get_trust_store_ca_certificates_bundle(TrustStoreArn=ts_arn)["Location"]
    _url, _route = ctx.endpoint_route(location)
    with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=30) as resp:
        fetched_bytes = resp.read()

    assert fetched_bytes == ca_bundle_bytes, (
        f"CA bundle content mismatch: uploaded {len(ca_bundle_bytes)} bytes, "
        f"fetched-back {len(fetched_bytes)} bytes (byte content differs)"
    )


def _short_name(ctx, prefix: str) -> str:
    # TrustStoreName only allows [a-zA-Z0-9-] (no underscores), max 32 chars.
    name = ctx.unique_name(f"{prefix}-").replace("_", "-")
    return name[:32].rstrip("-")


def _create_bucket(ctx, s3, bucket: str) -> None:
    # us-east-1 is the CreateBucket default and rejects an explicit LocationConstraint for it.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _generate_self_signed_ca_pem() -> bytes:
    tmpdir = tempfile.mkdtemp(prefix="sim2real-elbv2-ts-")
    try:
        key_path = os.path.join(tmpdir, "ca.key")
        cert_path = os.path.join(tmpdir, "ca.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "36500", "-keyout", key_path, "-out", cert_path,
                "-subj", "/CN=sim2real-elbv2-test-ca",
                "-addext", "basicConstraints=critical,CA:TRUE",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        with open(cert_path, "rb") as f:
            return f.read()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _wait_for_trust_store_active(elbv2, ts_arn: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        ts = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]
        last_status = ts["Status"]
        if last_status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"trust store never reached ACTIVE, last status={last_status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
