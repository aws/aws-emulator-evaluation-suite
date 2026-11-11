"""op-contract-getTrustStore."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getTrustStore"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTrustStore returns a just-created trust store by Identifier, while both an invalid-character
    Identifier and a well-formed nonexistent one fail identically with EntityNotFound and the exact message
    "The specified trust store does not exist."."""
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bundle_pem = _generate_self_signed_ca_bundle()

    bucket = ctx.unique_name("sim2real-truststore-").lower().replace("_", "-")
    key = "ca-bundle.pem"
    _create_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key=key, Body=bundle_pem.encode("utf-8"))

    name = ctx.unique_name("sim2real-truststore-")
    created = cf.create_trust_store(
        Name=name,
        CaCertificatesBundleSource={
            "CaCertificatesBundleS3Location": {"Bucket": bucket, "Key": key, "Region": ctx.region}
        },
    )["TrustStore"]
    store_id = created["Id"]
    ctx.on_cleanup(lambda: _delete_trust_store(ctx, store_id))

    # Positive control: the identifier of a real trust store resolves.
    got = cf.get_trust_store(Identifier=store_id)["TrustStore"]
    assert got["Id"] == store_id, f"expected GetTrustStore to resolve {store_id!r}, got {got['Id']!r}"

    malformed_code, malformed_msg = _error(lambda: cf.get_trust_store(Identifier="not a valid identifier !!"))
    if malformed_code == "UnsupportedOperation":
        raise AssertionError("GetTrustStore answered UnsupportedOperation")
    assert malformed_code == "EntityNotFound", (
        f"expected EntityNotFound for an identifier with invalid characters, got {malformed_code}"
    )
    assert malformed_msg == "The specified trust store does not exist.", f"unexpected message for an invalid identifier: {malformed_msg!r}"

    missing_code, missing_msg = _error(lambda: cf.get_trust_store(Identifier="TS00SIM2REALMISSING0"))
    assert missing_code == "EntityNotFound", (
        f"expected EntityNotFound for a well-formed but nonexistent identifier, got {missing_code}"
    )
    assert missing_msg == "The specified trust store does not exist.", f"unexpected message for a nonexistent identifier: {missing_msg!r}"
    assert missing_code == malformed_code, (
        "GetTrustStore should not distinguish identifier shape from resource existence"
    )


def _generate_self_signed_ca_bundle() -> str:
    import os
    import subprocess
    import tempfile

    from fidelity_tests_runner import require_tools

    require_tools("openssl")
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


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, s3, bucket))


def _delete_bucket(ctx, s3, bucket: str) -> None:
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _delete_trust_store(ctx, store_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_trust_store(Identifier=store_id)["ETag"]
        cf.delete_trust_store(Id=store_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises.
    A call that succeeds raises AssertionError, so an accepted call is never read as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
