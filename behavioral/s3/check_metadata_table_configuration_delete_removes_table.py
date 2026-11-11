"""metadata-table-configuration-delete-removes-table."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "metadata-table-configuration-delete-removes-table"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteBucketMetadataConfiguration, Get and journal-table updates fail with
    MetadataConfigurationNotFound; a fresh configuration can then be created and read again."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    ctx.on_cleanup(lambda: _delete_metadata_tables(ctx, bucket))
    ctx.on_cleanup(lambda: _safe_delete_config(s3, bucket))

    _create_metadata_configuration(s3, bucket)

    # Positive control: the configuration exists and is retrievable right after creation.
    before = s3.get_bucket_metadata_configuration(Bucket=bucket)
    journal = before["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]["JournalTableConfigurationResult"]
    assert journal["TableStatus"] in ("CREATING", "ACTIVE"), f"journal TableStatus {journal['TableStatus']!r}"
    assert journal["RecordExpiration"]["Expiration"] == "DISABLED", (
        f"journal RecordExpiration {journal['RecordExpiration']!r}, expected the DISABLED value created"
    )

    s3.delete_bucket_metadata_configuration(Bucket=bucket)

    code, message = _error(lambda: s3.get_bucket_metadata_configuration(Bucket=bucket))
    assert code == "MetadataConfigurationNotFound", code
    assert message == "The metadata configuration was not found", message

    # A mutation on the now-dead configuration fails the same way rather than silently
    # reviving or no-op'ing it.
    mutate_code, mutate_message = _error(
        lambda: s3.update_bucket_metadata_journal_table_configuration(
            Bucket=bucket,
            JournalTableConfiguration={"RecordExpiration": {"Expiration": "ENABLED", "Days": 30}},
        )
    )
    assert mutate_code == "MetadataConfigurationNotFound", mutate_code
    assert mutate_message == "The metadata configuration was not found", mutate_message

    # The bucket is reusable: a fresh configuration can be created and retrieved again.
    _create_metadata_configuration(s3, bucket)
    after = s3.get_bucket_metadata_configuration(Bucket=bucket)
    after_journal = after["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]["JournalTableConfigurationResult"]
    assert after_journal["TableStatus"] in ("CREATING", "ACTIVE"), (
        f"recreated journal TableStatus {after_journal['TableStatus']!r}"
    )
    assert after_journal["RecordExpiration"]["Expiration"] == "DISABLED", (
        f"recreated journal RecordExpiration {after_journal['RecordExpiration']!r}, expected the DISABLED value created"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("s3meta-src-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


def _create_metadata_configuration(s3, bucket: str) -> None:
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


def _safe_delete_config(s3, bucket: str) -> None:
    try:
        s3.delete_bucket_metadata_configuration(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("MetadataConfigurationNotFound", "NoSuchBucket"):
            raise


def _error(fn):
    """Call fn(); return its botocore (Code, Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
