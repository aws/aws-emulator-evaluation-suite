"""deep-s3-storage-class-deep-archive-expedited-restore-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-storage-class-deep-archive-expedited-restore-rejected"
GROUP = "storage-class"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RestoreObject with Tier=Expedited on a DEEP_ARCHIVE object is refused with InvalidTier and its
    exact message and starts no restore; a Bulk restore then answers 202 with an ongoing Restore header,
    and a repeat is RestoreAlreadyInProgress."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dsc-dx-")
    key = "archive/deep.bin"

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    s3.put_object(Bucket=bucket, Key=key, Body=b"deep-archive-restore-tier", StorageClass="DEEP_ARCHIVE")
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head.get("StorageClass") == "DEEP_ARCHIVE", f"StorageClass was {head.get('StorageClass')!r}"
    assert "Restore" not in head, f"fresh object carried Restore={head.get('Restore')!r}"

    # Break exactly one thing: the Expedited tier.
    code = _error(lambda: s3.restore_object(
        Bucket=bucket, Key=key,
        RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Expedited"}},
    ))
    assert code == ("InvalidTier", "Retrieval option is not supported by this storage class."), (
        f"Expedited restore of DEEP_ARCHIVE returned {code!r}, expected InvalidTier with AWS's "
        f"exact message"
    )

    after = s3.head_object(Bucket=bucket, Key=key)
    assert "Restore" not in after, (
        f"a refused Expedited restore still left Restore={after.get('Restore')!r} on the object"
    )
    assert after.get("StorageClass") == "DEEP_ARCHIVE", f"StorageClass changed to {after.get('StorageClass')!r}"

    # Positive control: the same object, same Days, Bulk tier -> an accepted, visible restore.
    resp = s3.restore_object(
        Bucket=bucket, Key=key,
        RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Bulk"}},
    )
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 202, f"first Bulk restore returned HTTP {status}, expected 202 Accepted"

    restore = _poll_restore_header(s3, bucket, key)
    assert restore == 'ongoing-request="true"', (
        f"after an accepted Bulk restore HeadObject Restore was {restore!r}, expected ongoing-request=\"true\""
    )

    # A second identical request while the first is in flight is refused.
    dup = _error(lambda: s3.restore_object(
        Bucket=bucket, Key=key,
        RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Bulk"}},
    ))
    assert dup == ("RestoreAlreadyInProgress", "Object restore is already in progress"), (
        f"duplicate Bulk restore returned {dup!r}"
    )


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
