"""bucket-metadata-journal-table-update."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-metadata-journal-table-update"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After a base S3 Metadata configuration exists, UpdateBucketMetadataJournalTableConfiguration
    modifies journal-table record expiration and GetBucketMetadataConfiguration reflects the update."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-metajrn-")
    _create_bucket(s3, ctx, bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    ctx.on_cleanup(lambda: _delete_metadata_tables(ctx, bucket))
    ctx.on_cleanup(lambda: _safe(s3.delete_bucket_metadata_configuration, Bucket=bucket))

    base_cfg = {"JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}}}
    try:
        s3.create_bucket_metadata_configuration(Bucket=bucket, MetadataConfiguration=base_cfg)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError("insufficient permissions to create S3 Metadata configuration") from exc
        raise

    before = _poll_until(
        lambda: s3.get_bucket_metadata_configuration(Bucket=bucket),
        lambda r: "JournalTableConfigurationResult" in r["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"],
        timeout_s=60,
        interval_s=3,
    )
    before_journal = before["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"][
        "JournalTableConfigurationResult"
    ]
    assert before_journal["RecordExpiration"]["Expiration"] == "DISABLED", (
        f"expected freshly created journal table to report RecordExpiration DISABLED, "
        f"got {before_journal['RecordExpiration']!r}"
    )

    # Immediately after CreateBucketMetadataConfiguration, the journal table can still be
    # settling; a mutation right away may transiently fail with InvalidRequest. Retry the
    # update within a bounded window rather than assuming it always succeeds on the first try.
    _update_journal_table_with_retry(
        s3, bucket, {"RecordExpiration": {"Expiration": "ENABLED", "Days": 30}}
    )

    after = _poll_until(
        lambda: s3.get_bucket_metadata_configuration(Bucket=bucket),
        lambda r: r["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"][
            "JournalTableConfigurationResult"
        ]["RecordExpiration"]["Expiration"]
        == "ENABLED",
        timeout_s=60,
        interval_s=3,
    )
    after_journal = after["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"][
        "JournalTableConfigurationResult"
    ]
    assert after_journal["RecordExpiration"]["Expiration"] == "ENABLED", (
        f"expected UpdateBucketMetadataJournalTableConfiguration to flip Expiration to ENABLED, "
        f"GetBucketMetadataConfiguration still reports {after_journal['RecordExpiration']!r}"
    )
    assert after_journal["RecordExpiration"]["Days"] == 30, (
        f"expected the updated journal table RecordExpiration.Days to be 30, "
        f"got {after_journal['RecordExpiration'].get('Days')!r}"
    )


def _create_bucket(s3, ctx, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)


def _safe(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("MetadataConfigurationNotFound", "NoSuchBucket"):
            raise


def _update_journal_table_with_retry(s3, bucket, journal_table_configuration, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            s3.update_bucket_metadata_journal_table_configuration(
                Bucket=bucket, JournalTableConfiguration=journal_table_configuration
            )
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InvalidRequest":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last result: {last!r}")


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
