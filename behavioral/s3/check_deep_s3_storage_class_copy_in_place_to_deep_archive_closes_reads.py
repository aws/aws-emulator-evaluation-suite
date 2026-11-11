"""deep-s3-storage-class-copy-in-place-to-deep-archive-closes-reads."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-storage-class-copy-in-place-to-deep-archive-closes-reads"
GROUP = "storage-class"
SERVICES = ["s3"]

_GET_ARCHIVED = ("InvalidObjectState", "The operation is not valid for the object's storage class")
_COPY_ARCHIVED = ("InvalidObjectState", "Operation is not valid for the source object's storage class")


@tags("cap:c2", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """An in-place CopyObject to DEEP_ARCHIVE keeps size and ETag but closes reads: GetObject and
    a copy back to STANDARD are refused with InvalidObjectState, and the class stays."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dsc-cp-")
    key = "data/object.bin"
    body = b"readable-until-archived-0123456789"

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    etag = s3.put_object(Bucket=bucket, Key=key, Body=body)["ETag"]
    before = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert before == body, f"STANDARD GetObject returned {before!r}, expected {body!r}"

    s3.copy_object(Bucket=bucket, Key=key, CopySource={"Bucket": bucket, "Key": key},
                   StorageClass="DEEP_ARCHIVE")

    head = s3.head_object(Bucket=bucket, Key=key)
    assert head.get("StorageClass") == "DEEP_ARCHIVE", f"after re-class StorageClass was {head.get('StorageClass')!r}"
    assert head.get("ContentLength") == len(body), f"after re-class ContentLength was {head.get('ContentLength')!r}"
    assert head["ETag"] == etag, f"after re-class ETag {head['ETag']!r} != original {etag!r}"
    listed = {o["Key"]: o.get("StorageClass") for o in
              s3.list_objects_v2(Bucket=bucket, Prefix="data/").get("Contents", [])}
    assert listed == {key: "DEEP_ARCHIVE"}, f"ListObjectsV2 after re-class: {listed!r}"

    got = _error(lambda: s3.get_object(Bucket=bucket, Key=key))
    assert got == _GET_ARCHIVED, f"GetObject after re-class returned {got!r}, expected {_GET_ARCHIVED!r}"

    back = _error(lambda: s3.copy_object(
        Bucket=bucket, Key=key, CopySource={"Bucket": bucket, "Key": key}, StorageClass="STANDARD",
    ))
    assert back == _COPY_ARCHIVED, f"copy back to STANDARD returned {back!r}, expected {_COPY_ARCHIVED!r}"
    still = s3.head_object(Bucket=bucket, Key=key)
    assert still.get("StorageClass") == "DEEP_ARCHIVE", f"refused copy-back changed class to {still.get('StorageClass')!r}"


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


def _error(fn):
    """Call fn(); return the ClientError (code, message); a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
