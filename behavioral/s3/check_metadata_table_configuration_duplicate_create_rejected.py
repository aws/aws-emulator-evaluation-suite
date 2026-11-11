"""metadata-table-configuration-duplicate-create-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metadata-table-configuration-duplicate-create-rejected"
GROUP = "e2e"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A second CreateBucketMetadataConfiguration fails with MetadataConfigurationAlreadyExists;
    the original stays ACTIVE on the same table, and object put/get still works."""
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-metatbl-dup-")
    s3.create_bucket(Bucket=bucket, **_location_kwargs(ctx))
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    ctx.on_cleanup(lambda: _delete_metadata_tables(ctx, bucket))

    s3.create_bucket_metadata_configuration(
        Bucket=bucket,
        MetadataConfiguration={
            "JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}}
        },
    )
    ctx.on_cleanup(lambda: s3.delete_bucket_metadata_configuration(Bucket=bucket))
    _poll_metadata_table_active(ctx, bucket)
    original_table_arn = _get_journal_table_arn(ctx, bucket)

    code, message = _error(
        lambda: s3.create_bucket_metadata_configuration(
            Bucket=bucket,
            MetadataConfiguration={
                "JournalTableConfiguration": {
                    "RecordExpiration": {"Expiration": "ENABLED", "Days": 30}
                }
            },
        )
    )
    assert code == "MetadataConfigurationAlreadyExists", (
        f"expected MetadataConfigurationAlreadyExists, got {code}"
    )
    assert message == "The metadata configuration already exists", message

    # Effect absent: still ACTIVE on the original journal table.
    _poll_metadata_table_active(ctx, bucket)
    current_table_arn = _get_journal_table_arn(ctx, bucket)
    assert current_table_arn == original_table_arn, (
        f"expected the rejected duplicate to leave the original table {original_table_arn!r} in "
        f"place, got {current_table_arn!r}"
    )

    # Positive control: ordinary data-plane access still works.
    key = "still-works.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"still-works")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert body == b"still-works", f"expected b'still-works', got {body!r}"


def _error(fn):
    """Call fn(); return its botocore (Code, Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the duplicate CreateBucketMetadataConfiguration to fail, but it SUCCEEDED "
        f"and returned {result!r}"
    )


def _location_kwargs(ctx: Any) -> dict:
    if ctx.region == "us-east-1":
        return {}
    return {"CreateBucketConfiguration": {"LocationConstraint": ctx.region}}


def _delete_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _get_journal_table_arn(ctx: Any, bucket: str) -> str:
    s3 = ctx.client("s3")
    result = s3.get_bucket_metadata_configuration(Bucket=bucket)
    result = result["GetBucketMetadataConfigurationResult"]
    return result["MetadataConfigurationResult"]["JournalTableConfigurationResult"]["TableArn"]


def _poll_metadata_table_active(ctx: Any, bucket: str, timeout_s: float = 180.0) -> None:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        result = s3.get_bucket_metadata_configuration(Bucket=bucket)
        result = result["GetBucketMetadataConfigurationResult"]
        journal = result["MetadataConfigurationResult"]["JournalTableConfigurationResult"]
        last_status = journal.get("TableStatus")
        if last_status == "ACTIVE":
            return
        if last_status == "FAILED":
            raise AssertionError(f"metadata configuration failed: {journal.get('Error')}")
        time.sleep(3)
    raise AssertionError(f"metadata configuration never became ACTIVE, last status={last_status}")


def _delete_metadata_tables(ctx, bucket: str) -> None:
    """Delete the metadata tables and namespace left in the AWS-managed table bucket; deleting the
    configuration or the bucket keeps them, and they bill."""
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

