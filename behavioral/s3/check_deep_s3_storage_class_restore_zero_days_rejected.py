"""deep-s3-storage-class-restore-zero-days-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-storage-class-restore-zero-days-rejected"
GROUP = "storage-class"
SERVICES = ["s3"]

_ZERO_DAYS_MESSAGE = "restoration days should be at least 1"


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RestoreObject with Days=0 on a GLACIER object is refused with InvalidArgument and its exact
    message and starts no restore (no Restore header, GetObject still InvalidObjectState); Days=1 is then
    accepted with 202 and an ongoing Restore header."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dsc-rz-")
    key = "archive/glacier.bin"

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    s3.put_object(Bucket=bucket, Key=key, Body=b"glacier-zero-days", StorageClass="GLACIER")
    assert s3.head_object(Bucket=bucket, Key=key).get("StorageClass") == "GLACIER"

    refusal = _error(lambda: s3.restore_object(
        Bucket=bucket, Key=key,
        RestoreRequest={"Days": 0, "GlacierJobParameters": {"Tier": "Bulk"}},
    ))
    assert refusal == ("InvalidArgument", _ZERO_DAYS_MESSAGE), (
        f"RestoreObject Days=0 returned {refusal!r}, expected InvalidArgument"
    )

    head = s3.head_object(Bucket=bucket, Key=key)
    assert "Restore" not in head, f"a refused Days=0 restore left Restore={head.get('Restore')!r}"

    get_refusal = _error(lambda: s3.get_object(Bucket=bucket, Key=key))
    assert get_refusal == ("InvalidObjectState", "The operation is not valid for the object's storage class"), (
        f"GetObject after refused restore returned {get_refusal!r}"
    )

    # Positive control: identical request, Days=1.
    resp = s3.restore_object(
        Bucket=bucket, Key=key,
        RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Bulk"}},
    )
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 202, f"Days=1 restore returned HTTP {status}, expected 202"
    header = _poll_restore_header(s3, bucket, key)
    assert header == 'ongoing-request="true"', f"Restore header after Days=1 was {header!r}"


def _poll_restore_header(s3, bucket: str, key: str, attempts: int = 20, delay: float = 3.0):
    value = None
    for _ in range(attempts):
        value = s3.head_object(Bucket=bucket, Key=key).get("Restore")
        if value:
            return value
        time.sleep(delay)
    return value


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
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message). An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
