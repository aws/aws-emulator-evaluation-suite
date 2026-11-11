"""copy-object-glacier-not-in-active-tier-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-object-glacier-not-in-active-tier-error"
GROUP = "error-semantics"
SERVICES = ["s3"]

_COPY_ARCHIVED = ("InvalidObjectState", "Operation is not valid for the source object's storage class")
_HEAD_ABSENT = ("404", 'Not Found')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject sourced from a GLACIER-class object that has not been restored to the
    active tier returns InvalidObjectState and the destination object is never
    created; the same CopyObject call against a STANDARD source succeeds byte-for-byte."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-")
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    standard_key = "source-standard.bin"
    standard_body = b"hot-data-copies-fine" * 10
    s3.put_object(Bucket=bucket, Key=standard_key, Body=standard_body)

    glacier_key = "source-glacier.bin"
    glacier_body = b"cold-archived-data" * 10
    s3.put_object(Bucket=bucket, Key=glacier_key, Body=glacier_body, StorageClass="GLACIER")
    head = s3.head_object(Bucket=bucket, Key=glacier_key)
    assert head["StorageClass"] == "GLACIER", f"expected GLACIER storage class, got {head.get('StorageClass')!r}"

    # Positive control: copying a STANDARD-tier source succeeds and is byte-identical.
    standard_dest_key = "dest-from-standard.bin"
    s3.copy_object(Bucket=bucket, Key=standard_dest_key, CopySource={"Bucket": bucket, "Key": standard_key})
    copied_body = s3.get_object(Bucket=bucket, Key=standard_dest_key)["Body"].read()
    assert copied_body == standard_body, "copied STANDARD-tier object must be byte-identical to its source"

    # Negative: copying from the un-restored GLACIER source is rejected.
    glacier_dest_key = "dest-from-glacier.bin"
    refusal = _error(
        lambda: s3.copy_object(
            Bucket=bucket, Key=glacier_dest_key, CopySource={"Bucket": bucket, "Key": glacier_key}
        )
    )
    # Real S3 rejects CopyObject from an un-restored GLACIER source with InvalidObjectState
    # (the same code GetObject/HeadObject use for archived objects), not the
    # ObjectNotInActiveTierError name suggested by some documentation.
    assert refusal == _COPY_ARCHIVED, f"expected {_COPY_ARCHIVED!r}, got {refusal!r}"

    # The rejected copy must not have created a destination object.
    not_found = _error(lambda: s3.head_object(Bucket=bucket, Key=glacier_dest_key))
    assert not_found == _HEAD_ABSENT, f"expected the copy destination absent {_HEAD_ABSENT!r}, got {not_found!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A call that SUCCEEDS
    fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(s3, bucket: str, region: str) -> None:
    # us-east-1 rejects an explicit LocationConstraint on CreateBucket; every other region requires one.
    if region and region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    else:
        s3.create_bucket(Bucket=bucket)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
