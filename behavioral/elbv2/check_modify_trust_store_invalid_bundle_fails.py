"""modify-trust-store-invalid-bundle-fails."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-trust-store-invalid-bundle-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyTrustStore with a malformed CA bundle raises InvalidCaCertificatesBundleException,
    leaves the trust store's existing CA bundle and ACTIVE status untouched, and a subsequent
    modify with a genuinely valid bundle still succeeds (positive control)."""
    store = _create_active_trust_store(ctx)
    s3 = ctx.client("s3")
    elbv2 = ctx.client("elbv2")

    before = elbv2.describe_trust_stores(TrustStoreArns=[store["arn"]])["TrustStores"][0]
    assert before["Status"] == "ACTIVE", f"expected ACTIVE before modify, got {before['Status']}"
    ca_count_before = before["NumberOfCaCertificates"]

    bad_key = "bad-bundle.txt"
    s3.put_object(Bucket=store["bucket"], Key=bad_key, Body=b"this is not a valid CA certificate bundle")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=store["bucket"], Key=bad_key))

    code, message = _error(
        lambda: elbv2.modify_trust_store(
            TrustStoreArn=store["arn"],
            CaCertificatesBundleS3Bucket=store["bucket"],
            CaCertificatesBundleS3Key=bad_key,
        )
    )
    assert code == "InvalidCaCertificatesBundle", (
        f"expected InvalidCaCertificatesBundleException, got {code!r}"
    )
    expected = "CA certificate bundle does not contain any certificates"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = elbv2.describe_trust_stores(TrustStoreArns=[store["arn"]])["TrustStores"][0]
    assert after["Status"] == "ACTIVE", (
        f"trust store must remain ACTIVE after a rejected modify, got {after['Status']}"
    )
    assert after["NumberOfCaCertificates"] == ca_count_before, (
        f"CA certificate count must be unchanged after a rejected modify: "
        f"before={ca_count_before} after={after['NumberOfCaCertificates']}"
    )

    good_pem = _generate_self_signed_ca_pem("sim2real-trust-store-ca-2")
    good_key = "good-bundle-2.pem"
    s3.put_object(Bucket=store["bucket"], Key=good_key, Body=good_pem.encode("utf-8"))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=store["bucket"], Key=good_key))

    _modify_with_retry(elbv2, store["arn"], store["bucket"], good_key)
    _wait_active(ctx, elbv2, store["arn"])


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _modify_with_retry(elbv2, arn, bucket, key, attempts=6, delay_s=5.0):
    """Absorbs S3 read-after-write propagation delay on the just-written good bundle."""
    last_exc = None
    for _ in range(attempts):
        try:
            elbv2.modify_trust_store(
                TrustStoreArn=arn, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key=key
            )
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "CaCertificatesBundleNotFound":
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _wait_active(ctx, elbv2, arn, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = elbv2.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]["Status"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"trust store did not return to ACTIVE after a valid modify (last status={status})",
    )


def _generate_self_signed_ca_pem(cn):
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        cert_path = os.path.join(d, "cert.pem")
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "365", "-nodes", "-subj", f"/CN={cn}",
        ]
        subprocess.run(cmd, check=True, capture_output=True, timeout=30)
        with open(cert_path, "r") as f:
            return f.read()


def _create_active_trust_store(ctx):
    elbv2 = ctx.client("elbv2")
    s3 = ctx.client("s3")
    pem = _generate_self_signed_ca_pem("sim2real-trust-store-ca")

    bucket = ctx.unique_name("sim2real-elbv2-ts-").lower().replace("_", "-")
    create_kwargs = {}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **create_kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})

    key = "ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=key, Body=pem.encode("utf-8"))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    name = ctx.unique_name("sim2real-ts-")
    resp = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key=key,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    arn = resp["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=arn))

    deadline = time.monotonic() + 90.0
    status = None
    while time.monotonic() < deadline:
        status = elbv2.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]["Status"]
        if status == "ACTIVE":
            break
        time.sleep(3.0)
    if status != "ACTIVE":
        raise AssertionError(
            f"trust store did not reach ACTIVE status in time (last status={status})",
        )

    return {"arn": arn, "bucket": bucket}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
