"""metadata-table-configuration-invalid-schema-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "metadata-table-configuration-invalid-schema-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]

# NOTE on the pinned error code: per API_RecordExpiration.html, when journal table record
# expiration is ENABLED, Days must be a whole number from 7 to 2147483647 ("Journal table records
# must be retained for a minimum of 7 days"). Days=1 violates that documented constraint, so the
# service must reject the request synchronously with InvalidRequest rather than silently
# clamping or accepting it.


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBucketMetadataConfiguration with RecordExpiration.Days below the 7-day minimum is rejected
    with InvalidRequest and its exact message and leaves no configuration (MetadataConfigurationNotFound),
    while a valid configuration is then created and reaches ACTIVE."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    ctx.on_cleanup(lambda: _delete_metadata_tables(ctx, bucket))

    code, message = _error(
        lambda: s3.create_bucket_metadata_configuration(
            Bucket=bucket,
            MetadataConfiguration={
                "JournalTableConfiguration": {
                    "RecordExpiration": {"Expiration": "ENABLED", "Days": 1}
                }
            },
        )
    )
    assert code == "InvalidRequest", code
    assert message == (
        "When RecordExpiration is set to ENABLED, the Days value must be specified. "
        "This value must be a whole number from 7 to 2147483647. "
        "Specify a valid Days value, and then try again."
    ), message

    # Effect absent: the rejected attempt left no configuration behind.
    absent_code, absent_message = _error(lambda: s3.get_bucket_metadata_configuration(Bucket=bucket))
    assert absent_code == "MetadataConfigurationNotFound", absent_code
    assert absent_message == "The metadata configuration was not found", absent_message

    # Positive control: a valid RecordExpiration is accepted.
    try:
        s3.create_bucket_metadata_configuration(
            Bucket=bucket,
            MetadataConfiguration={
                "JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}}
            },
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(
                "test role lacks the s3tables:* permissions CreateBucketMetadataConfiguration "
                "needs to provision the AWS-managed table bucket"
            ) from exc
        raise
    ctx.on_cleanup(lambda: _safe_delete_config(s3, bucket))

    journal = _poll_journal_terminal(s3, bucket)
    assert journal["TableStatus"] == "ACTIVE", journal


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("s3meta-src-")
    kwargs = {"Bucket": name}
    # us-east-1 rejects an explicit LocationConstraint for CreateBucket.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


def _safe_delete_config(s3, bucket: str) -> None:
    try:
        s3.delete_bucket_metadata_configuration(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("MetadataConfigurationNotFound", "NoSuchBucket"):
            raise


def _poll_journal_terminal(s3, bucket: str, timeout: float = 300.0, interval: float = 10.0) -> dict:
    """Poll the journal table until it leaves CREATING; raise on timeout."""
    deadline = time.monotonic() + timeout
    while True:
        got = s3.get_bucket_metadata_configuration(Bucket=bucket)
        journal = got["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"][
            "JournalTableConfigurationResult"
        ]
        if journal["TableStatus"] != "CREATING":
            return journal
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"journal table still CREATING after {timeout:.0f}s: {journal!r}"
            )
        time.sleep(interval)


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


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
