"""trust-store-stale-etag-versioning."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trust-store-stale-etag-versioning"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "s3"]

_ACTIVE_TIMEOUT_S = 600.0
_ACTIVE_POLL_S = 3.0


def _must_fail(fn):
    """Call fn(); return its botocore (code, message). A surprise 200 raises, so an
    over-permissive target never reads as a mismatched error code."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"AWS rejects this call, but it succeeded and returned {result!r}")


def _self_signed_ca_cert(common_name: str) -> bytes:
    """A throwaway CA certificate (PEM) with the given subject, for a trust store bundle."""
    with tempfile.TemporaryDirectory() as workdir:
        key_path = os.path.join(workdir, "ca.key")
        cert_path = os.path.join(workdir, "ca.crt")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
                "-subj", f"/CN={common_name}",
                "-keyout", key_path, "-out", cert_path,
            ],
            check=True, capture_output=True,
        )
        with open(cert_path, "rb") as f:
            return f.read()


def _wait_for_status(cf, store_id: str, target: str, deadline: float) -> dict:
    while True:
        current = cf.get_trust_store(Identifier=store_id)
        status = current["TrustStore"]["Status"]
        if status == target:
            return current
        assert status != "failed", f"trust store {store_id} entered failed status: {current['TrustStore'].get('Reason')!r}"
        assert time.monotonic() < deadline, (
            f"trust store {store_id} did not reach {target!r} before the deadline; last status {status!r}"
        )
        time.sleep(_ACTIVE_POLL_S)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTrustStore and DeleteTrustStore reject a well-formed but superseded If-Match ETag
    without changing the store, and each succeeds once given the store's current ETag."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    bucket = ctx.unique_name("sim2real-ts-bucket-")
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    key_one = "bundle-one.pem"
    key_two = "bundle-two.pem"
    key_three = "bundle-three.pem"
    cert_a = _self_signed_ca_cert(f"{bucket}-a")
    cert_b = _self_signed_ca_cert(f"{bucket}-b")
    cert_c = _self_signed_ca_cert(f"{bucket}-c")
    s3.put_object(Bucket=bucket, Key=key_one, Body=cert_a)
    s3.put_object(Bucket=bucket, Key=key_two, Body=cert_a + cert_b)
    s3.put_object(Bucket=bucket, Key=key_three, Body=cert_a + cert_b + cert_c)

    def _bundle_source(key: str) -> dict:
        return {"CaCertificatesBundleS3Location": {"Bucket": bucket, "Key": key, "Region": ctx.region}}

    name = ctx.unique_name("sim2real-truststore-")
    created = cf.create_trust_store(Name=name, CaCertificatesBundleSource=_bundle_source(key_one))
    store_id = created["TrustStore"]["Id"]

    def _cleanup() -> None:
        try:
            got = cf.get_trust_store(Identifier=store_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "EntityNotFound":
                return
            raise
        cf.delete_trust_store(Id=store_id, IfMatch=got["ETag"])

    ctx.on_cleanup(_cleanup)

    first = _wait_for_status(cf, store_id, "active", time.monotonic() + _ACTIVE_TIMEOUT_S)
    stale_etag = first["ETag"]

    # Rotate the bundle for real, so stale_etag no longer matches the live version.
    cf.update_trust_store(Id=store_id, IfMatch=stale_etag, CaCertificatesBundleSource=_bundle_source(key_two))
    rotated = _wait_for_status(cf, store_id, "active", time.monotonic() + _ACTIVE_TIMEOUT_S)
    assert rotated["TrustStore"]["NumberOfCaCertificates"] == 2, (
        f"expected 2 CA certificates after rotating to the two-cert bundle, "
        f"got {rotated['TrustStore']['NumberOfCaCertificates']}"
    )
    current_etag = rotated["ETag"]
    assert current_etag != stale_etag, "UpdateTrustStore must mint a new ETag on a real change"

    code, message = _must_fail(
        lambda: cf.update_trust_store(Id=store_id, IfMatch=stale_etag, CaCertificatesBundleSource=_bundle_source(key_three))
    )
    assert code == "PreconditionFailed", f"expected PreconditionFailed for a stale If-Match, got {code!r}"
    assert message == (
        "Your request is missing requirements for this operation. Update your request and try again."
    ), f"expected AWS's exact precondition message, got {message!r}"

    # The forbidden update did not land: still the two-cert bundle, not the three-cert one.
    untouched = cf.get_trust_store(Identifier=store_id)
    assert untouched["TrustStore"]["NumberOfCaCertificates"] == 2, (
        f"a rejected stale-etag update must not change the bundle, "
        f"got {untouched['TrustStore']['NumberOfCaCertificates']} certificates"
    )
    assert untouched["ETag"] == current_etag, "a rejected stale-etag update must not mint a new ETag"

    # Positive control: the identical update succeeds with the CURRENT ETag.
    cf.update_trust_store(Id=store_id, IfMatch=current_etag, CaCertificatesBundleSource=_bundle_source(key_three))
    advanced = _wait_for_status(cf, store_id, "active", time.monotonic() + _ACTIVE_TIMEOUT_S)
    assert advanced["TrustStore"]["NumberOfCaCertificates"] == 3, (
        f"expected 3 CA certificates after the current-etag update, "
        f"got {advanced['TrustStore']['NumberOfCaCertificates']}"
    )
    advanced_etag = advanced["ETag"]

    delete_code, delete_message = _must_fail(
        lambda: cf.delete_trust_store(Id=store_id, IfMatch=current_etag)
    )
    assert delete_code == "PreconditionFailed", f"expected PreconditionFailed deleting with a stale If-Match, got {delete_code!r}"
    assert delete_message == (
        "Your request is missing requirements for this operation. Update your request and try again."
    ), f"expected AWS's exact precondition message, got {delete_message!r}"

    # The forbidden delete did not land: an independent read still finds the store.
    still_there = cf.get_trust_store(Identifier=store_id)
    assert still_there["TrustStore"]["Id"] == store_id, "a rejected stale-etag delete must leave the store readable"

    # Positive control: the identical delete succeeds with the CURRENT ETag.
    cf.delete_trust_store(Id=store_id, IfMatch=advanced_etag)
    gone_code, gone_message = _must_fail(lambda: cf.get_trust_store(Identifier=store_id))
    assert gone_code == "EntityNotFound", f"expected EntityNotFound reading the deleted trust store, got {gone_code!r}"
    assert gone_message == "The specified trust store does not exist.", (
        f"expected AWS's exact not-found message, got {gone_message!r}"
    )


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        listing = s3.list_objects_v2(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    for obj in listing.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
