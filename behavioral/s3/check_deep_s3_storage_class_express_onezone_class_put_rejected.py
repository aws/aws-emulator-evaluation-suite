"""deep-s3-storage-class-express-onezone-class-put-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-storage-class-express-onezone-class-put-rejected"
GROUP = "storage-class"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject with StorageClass=EXPRESS_ONEZONE into a general-purpose bucket is refused with
    InvalidStorageClass and its exact message and writes nothing (HeadObject 404, empty listing); a
    STANDARD_IA write to the same key then succeeds."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dsc-ex-")
    key = "target/object.bin"
    body = b"express-onezone-refused"

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    err = _error(lambda: s3.put_object(Bucket=bucket, Key=key, Body=body, StorageClass="EXPRESS_ONEZONE"))
    assert err.get("Code") == "InvalidStorageClass", (
        f"PutObject StorageClass=EXPRESS_ONEZONE returned {err!r}, expected InvalidStorageClass"
    )
    assert err.get("Message") == "The storage class you specified is not valid", err.get("Message")

    missing = _error_code(lambda: s3.head_object(Bucket=bucket, Key=key))
    assert missing == "404", f"HeadObject after the refused PUT returned {missing!r}, expected 404"
    listed = s3.list_objects_v2(Bucket=bucket, Prefix="target/").get("Contents", [])
    assert listed == [], f"refused PUT still left objects under target/: {listed!r}"

    # Positive control: same key, same body, a valid general-purpose class.
    s3.put_object(Bucket=bucket, Key=key, Body=body, StorageClass="STANDARD_IA")
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head.get("StorageClass") == "STANDARD_IA", f"control StorageClass was {head.get('StorageClass')!r}"
    data = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert data == body, f"control GetObject returned {data!r}"


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


def _error_code(fn):
    """Call fn(); return its botocore Error code. An unexpected SUCCESS raises."""
    return _error(fn).get("Code")


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
