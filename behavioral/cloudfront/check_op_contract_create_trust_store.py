"""op-contract-createTrustStore."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createTrustStore"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrustStore with an S3 CA bundle returns a pending or active trust store with at least one CA
    certificate that GetTrustStore reads back; a bundle at a missing key is refused with EntityNotFound
    and the exact message, creating nothing, and the identical request succeeds once the object exists."""

    bundle_pem = _generate_self_signed_ca_bundle()

    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-truststore-").lower().replace("_", "-")
    key = "ca-bundle.pem"

    _create_bucket(ctx, s3, bucket)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "op-contract-create-trust-store"}]}
    )
    s3.put_object(Bucket=bucket, Key=key, Body=bundle_pem.encode("utf-8"))

    name = ctx.unique_name("sim2real-truststore-")
    resp = cf.create_trust_store(
        Name=name,
        CaCertificatesBundleSource={
            "CaCertificatesBundleS3Location": {"Bucket": bucket, "Key": key, "Region": ctx.region}
        },
        Tags={"Items": [{"Key": "sim2real", "Value": "op-contract-create-trust-store"}]},
    )
    store = resp["TrustStore"]
    store_id = store["Id"]
    ctx.on_cleanup(lambda: _delete_trust_store(ctx, store_id))

    assert store_id, f"expected CreateTrustStore to return an Id, got {store!r}"
    assert store["Name"] == name, f"expected TrustStore.Name {name!r}, got {store['Name']!r}"
    assert store["Status"] in ("pending", "active"), store["Status"]
    assert store["NumberOfCaCertificates"] >= 1, (
        f"expected NumberOfCaCertificates >= 1, got {store['NumberOfCaCertificates']}"
    )
    assert resp.get("ETag"), f"expected an ETag header on the CreateTrustStore response, got {resp!r}"

    got = cf.get_trust_store(Identifier=store_id)["TrustStore"]
    assert got["Id"] == store_id, f"expected GetTrustStore to return Id {store_id!r}, got {got['Id']!r}"

    # A bundle pointing at an S3 key that was never written is refused with EntityNotFound and
    # creates no trust store; once the object exists at that key, the identical request succeeds.
    missing_key = "no-such-object.pem"
    missing_name = ctx.unique_name("sim2real-truststore-missing-")
    code, message = _error(
        lambda: cf.create_trust_store(
            Name=missing_name,
            CaCertificatesBundleSource={
                "CaCertificatesBundleS3Location": {
                    "Bucket": bucket,
                    "Key": missing_key,
                    "Region": ctx.region,
                }
            },
        )
    )
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code}"
    expected = "The specified CA Certificates Bundle does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed_names = [t["Name"] for t in cf.list_trust_stores().get("TrustStoreList", [])]
    assert missing_name not in listed_names, "a rejected CreateTrustStore must not create a trust store"

    s3.put_object(Bucket=bucket, Key=missing_key, Body=bundle_pem.encode("utf-8"))
    restored = cf.create_trust_store(
        Name=missing_name,
        CaCertificatesBundleSource={
            "CaCertificatesBundleS3Location": {"Bucket": bucket, "Key": missing_key, "Region": ctx.region}
        },
        Tags={"Items": [{"Key": "sim2real", "Value": "op-contract-create-trust-store"}]},
    )
    restored_id = restored["TrustStore"]["Id"]
    ctx.on_cleanup(lambda: _delete_trust_store(ctx, restored_id))
    assert restored_id, f"expected the identical request to succeed once the object exists, got {restored!r}"


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
    """Call fn(); return the ClientError (code, message). An unexpected success raises,
    so a target that accepts what AWS refuses fails as an accepted call, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
