"""create-trust-store-invalid-bundle-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-trust-store-invalid-bundle-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

_ACTIVATE_TIMEOUT_S = 180.0
_ACTIVATE_INTERVAL_S = 5.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrustStore rejects a non-PEM S3 bundle with InvalidArgument and leaves no trust store,
    while a valid PEM CA bundle is accepted and reaches active (positive control)."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-ts-badbundle-")
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # S3 rejects a LocationConstraint that repeats us-east-1
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})

    good_key = "ca-bundle-good.pem"
    s3.put_object(Bucket=bucket, Key=good_key, Body=_generate_self_signed_ca_pem().encode("utf-8"))
    bad_key = "ca-bundle-bad.pem"
    s3.put_object(Bucket=bucket, Key=bad_key, Body=b"this is not a PEM certificate bundle at all")

    # Positive control: the identical call with a real CA bundle must succeed and activate.
    good_name = ctx.unique_name("sim2real-behav-ts-good-")
    created = cf.create_trust_store(
        Name=good_name,
        CaCertificatesBundleSource={
            "CaCertificatesBundleS3Location": {"Bucket": bucket, "Key": good_key, "Region": ctx.region}
        },
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    good_id = created["TrustStore"]["Id"]
    ctx.on_cleanup(lambda: _delete_trust_store(cf, good_id))

    status = _poll_until(
        lambda: cf.get_trust_store(Identifier=good_id)["TrustStore"],
        lambda ts: ts["Status"] in ("active", "failed"),
        timeout_s=_ACTIVATE_TIMEOUT_S,
        interval_s=_ACTIVATE_INTERVAL_S,
        description="positive-control trust store activation",
    )
    assert status["Status"] == "active", (
        f"positive control: a well-formed CA bundle must activate, got status={status['Status']!r} "
        f"reason={status.get('Reason')!r}"
    )
    reread_id = cf.get_trust_store(Identifier=good_id)["TrustStore"]["Id"]
    assert reread_id == good_id, f"independent GetTrustStore read: expected id {good_id!r}, got {reread_id!r}"

    # Same call with bundle content that is not PEM at all.
    bad_name = ctx.unique_name("sim2real-behav-ts-bad-")
    code, msg = _error(
        lambda: cf.create_trust_store(
            Name=bad_name,
            CaCertificatesBundleSource={
                "CaCertificatesBundleS3Location": {"Bucket": bucket, "Key": bad_key, "Region": ctx.region}
            },
        )
    )
    assert code == "InvalidArgument", f"expected InvalidArgument for a non-PEM CA bundle, got {code}"
    expected_msg = "The request contains an invalid CA Certificates Bundle."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Effect-absent: the rejected create must not have left a trust store behind, checked with an
    # independent read (ListTrustStores, not the mutating CreateTrustStore call itself).
    names = _list_all_trust_store_names(cf)
    assert bad_name not in names, f"rejected CreateTrustStore left {bad_name!r} visible in ListTrustStores"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected CreateTrustStore to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _list_all_trust_store_names(cf) -> list[str]:
    names: list[str] = []
    marker = None
    for _ in range(20):
        kwargs = {"Marker": marker} if marker else {}
        resp = cf.list_trust_stores(**kwargs)
        names.extend(t["Name"] for t in resp.get("TrustStoreList", []))
        marker = resp.get("NextMarker")
        if not marker:
            break
    return names


def _generate_self_signed_ca_pem() -> str:
    import os
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "ca.key")
        cert_path = os.path.join(d, "ca.pem")
        subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True, capture_output=True)
        subprocess.run(
            [
                "openssl", "req", "-x509", "-new", "-nodes",
                "-key", key_path, "-sha256", "-days", "3650",
                "-out", cert_path,
                "-subj", "/CN=sim2real-behavioral-check-ca",
            ],
            check=True,
            capture_output=True,
        )
        with open(cert_path) as f:
            return f.read()


def _delete_trust_store(cf, store_id):
    try:
        etag = cf.get_trust_store(Identifier=store_id)["ETag"]
        cf.delete_trust_store(Id=store_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


def _delete_bucket(s3, bucket):
    objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    if objs:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
