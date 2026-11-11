"""deep-s3-storage-class-restore-tier-downgrade-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-storage-class-restore-tier-downgrade-rejected"
GROUP = "storage-class"
SERVICES = ["s3"]
_IN_PROGRESS = "Object restore is already in progress"


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """During a Bulk restore of a GLACIER object, a Standard-tier RestoreObject is accepted (202) as an
    upgrade, while repeating Bulk and a Bulk after the upgrade are refused with RestoreAlreadyInProgress
    and its exact message; the restore stays ongoing."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dsc-tu-")
    key = "archive/glacier.bin"

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    s3.put_object(Bucket=bucket, Key=key, Body=b"glacier-tier-upgrade", StorageClass="GLACIER")
    assert s3.head_object(Bucket=bucket, Key=key).get("StorageClass") == "GLACIER"

    def restore(tier: str):
        return s3.restore_object(
            Bucket=bucket, Key=key,
            RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": tier}},
        )

    first = restore("Bulk")["ResponseMetadata"]["HTTPStatusCode"]
    assert first == 202, f"initial Bulk restore returned HTTP {first}, expected 202"
    header = _poll_restore_header(s3, bucket, key)
    assert header == 'ongoing-request="true"', f"Restore header after Bulk was {header!r}"

    same, same_message = _error_code(lambda: restore("Bulk"))
    assert same == "RestoreAlreadyInProgress", f"repeating the in-flight Bulk tier returned {same!r}"
    assert same_message == _IN_PROGRESS, f"repeating the in-flight Bulk tier said {same_message!r}"

    # Positive control: the upgrade to a faster tier is accepted.
    upgraded = restore("Standard")["ResponseMetadata"]["HTTPStatusCode"]
    assert upgraded == 202, f"Bulk->Standard upgrade returned HTTP {upgraded}, expected 202"

    # Break exactly one thing: go back down to the slower tier.
    down, down_message = _error_code(lambda: restore("Bulk"))
    assert down == "RestoreAlreadyInProgress", f"Standard->Bulk downgrade returned {down!r}"
    assert down_message == _IN_PROGRESS, f"Standard->Bulk downgrade said {down_message!r}"

    still = s3.head_object(Bucket=bucket, Key=key)
    assert still.get("Restore") == 'ongoing-request="true"', (
        f"after the refused downgrade the Restore header was {still.get('Restore')!r}"
    )
    assert still.get("StorageClass") == "GLACIER", f"StorageClass changed to {still.get('StorageClass')!r}"


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


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
