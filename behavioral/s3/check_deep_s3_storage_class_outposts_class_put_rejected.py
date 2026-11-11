"""deep-s3-storage-class-outposts-class-put-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-storage-class-outposts-class-put-rejected"
GROUP = "storage-class"
SERVICES = ["s3"]

#: S3's refusal of a storage class the bucket cannot hold, as real S3 returns it.
_INVALID_STORAGE_CLASS = ("InvalidStorageClass", "The storage class you specified is not valid")
#: S3's refusal of HeadObject on a key that does not exist (a HEAD response has no body), as real S3 returns it.
_NOT_FOUND = ("404", "Not Found")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject with StorageClass=OUTPOSTS into a regional general-purpose bucket is refused with
    InvalidStorageClass and writes nothing (HeadObject 404, empty listing); a ONEZONE_IA write to the
    same key then succeeds."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dsc-op-")
    key = "target/object.bin"
    body = b"outposts-class-refused"

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    code = _error(lambda: s3.put_object(Bucket=bucket, Key=key, Body=body, StorageClass="OUTPOSTS"))
    assert code == _INVALID_STORAGE_CLASS, f"PutObject StorageClass=OUTPOSTS returned {code!r}, expected InvalidStorageClass"

    missing = _error(lambda: s3.head_object(Bucket=bucket, Key=key))
    assert missing == _NOT_FOUND, f"HeadObject after the refused PUT returned {missing!r}, expected 404"
    listed = s3.list_objects_v2(Bucket=bucket, Prefix="target/").get("Contents", [])
    assert listed == [], f"refused PUT still left objects under target/: {listed!r}"

    # Positive control: same key, same body, a valid class.
    s3.put_object(Bucket=bucket, Key=key, Body=body, StorageClass="ONEZONE_IA")
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head.get("StorageClass") == "ONEZONE_IA", f"control StorageClass was {head.get('StorageClass')!r}"
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


def _error(fn):
    """Return the ClientError (Code, Message) of fn(); raise AssertionError when fn() succeeds."""
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
