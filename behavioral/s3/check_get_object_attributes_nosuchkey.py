"""get-object-attributes-nosuchkey."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-object-attributes-nosuchkey"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObjectAttributes on a missing key returns NoSuchKey rather than an
    empty/partial attribute set."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    err = _client_error(
        lambda: s3.get_object_attributes(
            Bucket=bucket,
            Key="does-not-exist.bin",
            ObjectAttributes=["ObjectSize", "ETag", "StorageClass"],
        )
    )
    assert err.get("Code") == "NoSuchKey", f"expected NoSuchKey, got {err!r}"
    assert err.get("Message") == "The specified key does not exist.", err

    # Sanity: a real object returns real attributes.
    key = "real-object.bin"
    body = b"attribute-check-payload"
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    attrs = s3.get_object_attributes(
        Bucket=bucket, Key=key, ObjectAttributes=["ObjectSize", "ETag", "StorageClass"]
    )
    assert attrs["ObjectSize"] == len(body)
    assert attrs["StorageClass"] == "STANDARD"


def _create_bucket(ctx):
    """Create a general-purpose S3 bucket and register full cleanup."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        try:
            resp = s3.list_object_versions(Bucket=name)
            for v in resp.get("Versions", []):
                s3.delete_object(Bucket=name, Key=v["Key"], VersionId=v["VersionId"])
            for m in resp.get("DeleteMarkers", []):
                s3.delete_object(Bucket=name, Key=m["Key"], VersionId=m["VersionId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=name):
                for u in page.get("Uploads", []):
                    s3.abort_multipart_upload(Bucket=name, Key=u["Key"], UploadId=u["UploadId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
                raise
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _client_error(fn):
    """Call fn(); return the ClientError's Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected NoSuchKey, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
