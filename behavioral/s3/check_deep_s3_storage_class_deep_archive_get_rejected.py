"""deep-s3-storage-class-deep-archive-get-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-storage-class-deep-archive-get-rejected"
GROUP = "storage-class"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An object that HeadObject and ListObjectsV2 report as DEEP_ARCHIVE with its exact size is refused
    by GetObject, whole and ranged, with InvalidObjectState and its exact message, while a STANDARD
    sibling serves its bytes before and after."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dsc-da-")
    key = "archive/deep.bin"
    body = b"deep-archive-payload-0123456789"
    control_key = "warm/standard.bin"
    control_body = b"standard-control-payload"

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    # Positive control: GetObject works in this bucket for an active-tier object.
    s3.put_object(Bucket=bucket, Key=control_key, Body=control_body)
    got = s3.get_object(Bucket=bucket, Key=control_key)["Body"].read()
    assert got == control_body, f"STANDARD control returned {got!r}, expected {control_body!r}"

    s3.put_object(Bucket=bucket, Key=key, Body=body, StorageClass="DEEP_ARCHIVE")

    head = s3.head_object(Bucket=bucket, Key=key)
    assert head.get("StorageClass") == "DEEP_ARCHIVE", (
        f"HeadObject StorageClass was {head.get('StorageClass')!r}, expected 'DEEP_ARCHIVE'"
    )
    assert head.get("ContentLength") == len(body), (
        f"HeadObject ContentLength was {head.get('ContentLength')!r}, expected {len(body)}"
    )
    assert "Restore" not in head, f"a never-restored object carried Restore={head.get('Restore')!r}"

    listed = [o for o in s3.list_objects_v2(Bucket=bucket, Prefix="archive/").get("Contents", [])]
    assert [o["Key"] for o in listed] == [key], f"ListObjectsV2 under archive/ returned {listed!r}"
    assert listed[0].get("StorageClass") == "DEEP_ARCHIVE", (
        f"ListObjectsV2 StorageClass was {listed[0].get('StorageClass')!r}, expected 'DEEP_ARCHIVE'"
    )
    assert listed[0].get("Size") == len(body), f"ListObjectsV2 Size was {listed[0].get('Size')!r}"

    code = _error(lambda: s3.get_object(Bucket=bucket, Key=key))
    assert code == ("InvalidObjectState", "The operation is not valid for the object's storage class"), (
        f"GetObject on DEEP_ARCHIVE returned {code!r}, expected InvalidObjectState with AWS's "
        f"exact message"
    )

    ranged = _error(lambda: s3.get_object(Bucket=bucket, Key=key, Range="bytes=0-3"))
    assert ranged == ("InvalidObjectState", "The operation is not valid for the object's storage class"), (
        f"ranged GetObject on DEEP_ARCHIVE returned {ranged!r}, expected InvalidObjectState"
    )

    # The refusal is per-object, not a bucket-wide break.
    again = s3.get_object(Bucket=bucket, Key=control_key)["Body"].read()
    assert again == control_body, f"STANDARD control after refusal returned {again!r}"


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
    """Call fn(); return its botocore (Error code, Error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
