"""trust-store-lifecycle."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trust-store-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudfront"]

_ACTIVATE_TIMEOUT_S = 600.0
_ACTIVATE_INTERVAL_S = 2.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Trust stores support create->get->update->delete->list, activating a real CA bundle from S3."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    bucket = ctx.unique_name("sim2real-cf-truststore-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        # us-east-1 is the one region where S3 rejects an explicit LocationConstraint.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "1"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    ca_pem_v1 = _generate_self_signed_ca_pem("sim2real-test-ca-1")
    s3.put_object(Bucket=bucket, Key="ca-bundle-v1.pem", Body=ca_pem_v1)

    name = ctx.unique_name("sim2real-truststore-")
    if not hasattr(cf, "create_trust_store"):
        raise AssertionError("installed botocore does not support CreateTrustStore")

    try:
        created = cf.create_trust_store(
            Name=name,
            CaCertificatesBundleSource={
                "CaCertificatesBundleS3Location": {
                    "Bucket": bucket,
                    "Key": "ca-bundle-v1.pem",
                    "Region": ctx.region,
                }
            },
            Tags={"Items": [{"Key": "sim2real-check", "Value": "true"}]},
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("UnsupportedOperation", "AccessDenied"):
            raise AssertionError(f"trust stores unavailable for this account/region: {code}") from exc
        raise

    store_id = created["TrustStore"]["Id"]

    def _cleanup() -> None:
        try:
            got = cf.get_trust_store(Identifier=store_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityNotFound":
                return
            raise
        cf.delete_trust_store(Id=store_id, IfMatch=got["ETag"])

    ctx.on_cleanup(_cleanup)

    etag = _wait_trust_store_status(ctx, store_id, "active")
    got = cf.get_trust_store(Identifier=store_id)
    count_v1 = got["TrustStore"]["NumberOfCaCertificates"]
    assert count_v1 == 1, f"expected 1 CA certificate from a single-cert bundle, got {count_v1}"

    listed = cf.list_trust_stores()
    ids = [t["Id"] for t in listed.get("TrustStoreList", [])]
    assert store_id in ids, f"trust store {store_id} not present in ListTrustStores: {ids}"

    ca_pem_v2 = _generate_self_signed_ca_pem("sim2real-test-ca-2")
    s3.put_object(Bucket=bucket, Key="ca-bundle-v2.pem", Body=ca_pem_v1 + ca_pem_v2)

    updated = cf.update_trust_store(
        Id=store_id,
        IfMatch=etag,
        CaCertificatesBundleSource={
            "CaCertificatesBundleS3Location": {
                "Bucket": bucket,
                "Key": "ca-bundle-v2.pem",
                "Region": ctx.region,
            }
        },
    )
    assert updated["ETag"] != etag, f"UpdateTrustStore must mint a new ETag, still {etag}"

    final_etag = _wait_trust_store_status(ctx, store_id, "active")
    reread = cf.get_trust_store(Identifier=store_id)
    assert reread["TrustStore"]["NumberOfCaCertificates"] == 2, "updated bundle must reflect the 2-cert bundle"

    cf.delete_trust_store(Id=store_id, IfMatch=final_etag)

    read_code, read_message = _error(lambda: cf.get_trust_store(Identifier=store_id))
    assert read_code == "EntityNotFound", f"expected EntityNotFound reading deleted trust store {store_id}, got {read_code}"
    expected_message = "The specified trust store does not exist."
    assert read_message == expected_message, f"expected message {expected_message!r}, got {read_message!r}"

    mutation_code, mutation_message = _error(
        lambda: cf.update_trust_store(
            Id=store_id,
            IfMatch=final_etag,
            CaCertificatesBundleSource={
                "CaCertificatesBundleS3Location": {
                    "Bucket": bucket,
                    "Key": "ca-bundle-v2.pem",
                    "Region": ctx.region,
                }
            },
        )
    )
    assert mutation_code == "EntityNotFound", (
        f"UpdateTrustStore on a deleted id must also fail with EntityNotFound, got {mutation_code}"
    )
    assert mutation_message == expected_message, f"expected message {expected_message!r}, got {mutation_message!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _generate_self_signed_ca_pem(common_name: str) -> bytes:
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        result = subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path,
                "-out",
                "-",
                "-days",
                "365",
                "-nodes",
                "-subj",
                f"/CN={common_name}",
            ],
            capture_output=True,
            check=True,
        )
        return result.stdout


def _wait_trust_store_status(ctx, store_id: str, want: str, timeout_s: float = _ACTIVATE_TIMEOUT_S) -> str:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = cf.get_trust_store(Identifier=store_id)
        last_status = resp["TrustStore"]["Status"]
        if last_status == want:
            return resp["ETag"]
        if last_status == "failed":
            raise AssertionError(f"trust store {store_id} entered failed state: {resp['TrustStore'].get('Reason')}")
        time.sleep(_ACTIVATE_INTERVAL_S)
    raise AssertionError(f"trust store {store_id} never reached '{want}' (last={last_status})")


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
