"""delete-bucket-with-metadata-table-configuration-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-bucket-with-metadata-table-configuration-blocked"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a bucket that does not exist, as real S3 returns it.
_NO_SUCH_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBucket on an empty bucket with an ACTIVE metadata journal configuration succeeds, and
    GetBucketMetadataConfiguration and a configuration change on the deleted bucket then fail with
    NoSuchBucket, the same answer a never-created bucket gets."""
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-meta-")
    s3.create_bucket(Bucket=bucket, **_bucket_location_kwargs(s3))
    # safety net only: the happy path below deletes the bucket itself once the
    # assertions it depends on are satisfied, so this is a no-op on that path and
    # only matters if an earlier assertion fails first.
    ctx.on_cleanup(lambda: _force_delete_bucket(ctx, bucket))
    ctx.on_cleanup(lambda: _delete_metadata_tables(ctx, bucket))

    s3.create_bucket_metadata_configuration(
        Bucket=bucket,
        MetadataConfiguration={"JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}}},
    )

    status = _poll_until(
        lambda: _metadata_table_status(s3, bucket),
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=180.0,
        description="journal table configuration reaching a terminal state",
    )
    assert status == "ACTIVE", f"expected journal table configuration ACTIVE, got {status}"

    # overly-permissive guard: while the configuration is active, an UNRELATED
    # nonexistent bucket must still be rejected as NoSuchBucket, not silently reused.
    stray_code = _error(lambda: s3.get_bucket_metadata_configuration(Bucket=ctx.unique_name("sim2real-meta-none-")))
    assert stray_code == _NO_SUCH_BUCKET, f"expected NoSuchBucket for a nonexistent bucket, got {stray_code!r}"

    # DeleteBucket succeeds even with the metadata configuration still active --
    # it is not blocked as a wrong-state precondition.
    s3.delete_bucket(Bucket=bucket)

    # effect: the bucket's identity (and therefore its metadata configuration) is
    # gone -- callers must see NoSuchBucket, not a residual metadata-configuration
    # response or a NoSuchConfiguration that would imply the bucket still exists.
    after_code = _poll_until(
        lambda: _error(lambda: s3.get_bucket_metadata_configuration(Bucket=bucket)),
        lambda code: code != _SUCCEEDED,
        timeout_s=60.0,
        description="metadata configuration read failing after bucket deletion",
    )
    assert after_code == _NO_SUCH_BUCKET, f"expected NoSuchBucket after bucket deletion, got {after_code!r}"

    # the dead identity is not just unreadable -- a mutation against it fails too.
    mutation_code = _error(lambda: s3.delete_bucket_metadata_configuration(Bucket=bucket))
    assert mutation_code == _NO_SUCH_BUCKET, (
        f"expected NoSuchBucket deleting the metadata configuration of a deleted bucket, got {mutation_code!r}"
    )


def _bucket_location_kwargs(s3):
    region = s3.meta.region_name
    # us-east-1 rejects an explicit LocationConstraint on CreateBucket outright.
    if region and region != "us-east-1":
        return {"CreateBucketConfiguration": {"LocationConstraint": region}}
    return {}


#: What _error returns when its call succeeds; no (code, message) pair can equal it.
_SUCCEEDED = "<the call succeeded>"


def _error(fn):
    """Return the ClientError (Code, Message) of fn(), or _SUCCEEDED when fn() succeeds.

    _SUCCEEDED equals no expected error, so an unexpected success fails every assert that names
    one; a poll for eventual-consistency teardown waits for anything other than _SUCCEEDED.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _SUCCEEDED


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 3.0, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _metadata_table_status(s3, bucket: str):
    resp = s3.get_bucket_metadata_configuration(Bucket=bucket)
    result = resp["GetBucketMetadataConfigurationResult"]
    return result["MetadataConfigurationResult"]["JournalTableConfigurationResult"]["TableStatus"]


def _force_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        s3.delete_bucket_metadata_configuration(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("MetadataConfigurationNotFound", "NoSuchBucket"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_metadata_tables(ctx, bucket: str) -> None:
    """Delete the journal and inventory tables, and their namespace, that the bucket's metadata
    configuration leaves in the account's AWS-managed table bucket: deleting the configuration
    or the bucket keeps them, and they bill. Only an already-absent table or namespace is
    tolerated."""
    from botocore.exceptions import ClientError

    tables = ctx.client("s3tables")
    arn = f"arn:aws:s3tables:{ctx.region}:{ctx.account}:bucket/aws-s3"
    namespace = f"b_{bucket}"
    try:
        for page in tables.get_paginator("list_tables").paginate(
            tableBucketARN=arn, namespace=namespace
        ):
            for table in page.get("tables", []):
                tables.delete_table(tableBucketARN=arn, namespace=namespace, name=table["name"])
        tables.delete_namespace(tableBucketARN=arn, namespace=namespace)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
