"""deep-s3-storage-class-glacier-ir-restore-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-storage-class-glacier-ir-restore-rejected"
GROUP = "storage-class"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GLACIER_IR object reads back byte for byte without a restore, and RestoreObject on it is
    refused with InvalidObjectState and its exact message, while a GLACIER sibling refuses GetObject
    instead."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dsc-ir-")
    ir_key = "ir/instant.bin"
    ir_body = b"glacier-instant-retrieval-bytes"
    gl_key = "gl/flexible.bin"

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    s3.put_object(Bucket=bucket, Key=ir_key, Body=ir_body, StorageClass="GLACIER_IR")
    s3.put_object(Bucket=bucket, Key=gl_key, Body=b"glacier-flexible-bytes", StorageClass="GLACIER")

    head = s3.head_object(Bucket=bucket, Key=ir_key)
    assert head.get("StorageClass") == "GLACIER_IR", f"HeadObject StorageClass was {head.get('StorageClass')!r}"

    # Positive: GLACIER_IR serves its bytes with no restore.
    got = s3.get_object(Bucket=bucket, Key=ir_key)
    data = got["Body"].read()
    assert data == ir_body, f"GLACIER_IR GetObject returned {data!r}, expected {ir_body!r}"
    assert got.get("StorageClass") == "GLACIER_IR", f"GetObject StorageClass was {got.get('StorageClass')!r}"

    # Break one thing: ask for a restore of an object that is already retrievable.
    err = _client_error(lambda: s3.restore_object(
        Bucket=bucket, Key=ir_key, RestoreRequest={"Days": 1},
    ))
    assert err.get("Code") == "InvalidObjectState", f"RestoreObject on GLACIER_IR returned {err!r}, expected InvalidObjectState"
    assert err.get("Message") == "Restore is not allowed for the object's current storage class", err

    after = s3.head_object(Bucket=bucket, Key=ir_key)
    assert "Restore" not in after, f"a refused restore left Restore={after.get('Restore')!r}"
    assert after.get("StorageClass") == "GLACIER_IR", f"StorageClass changed to {after.get('StorageClass')!r}"

    # Contrast: the GLACIER sibling is on the other side of the boundary.
    gl_err = _client_error(lambda: s3.get_object(Bucket=bucket, Key=gl_key))
    assert gl_err.get("Code") == "InvalidObjectState", f"GetObject on GLACIER sibling returned {gl_err!r}"
    assert gl_err.get("Message") == "The operation is not valid for the object's storage class", gl_err


def _bucket_kwargs(ctx, bucket: str) -> dict:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    return kwargs


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        for upload in page.get("Uploads", []):
            s3.abort_multipart_upload(Bucket=bucket, Key=upload["Key"], UploadId=upload["UploadId"])
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    s3.delete_bucket(Bucket=bucket)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
