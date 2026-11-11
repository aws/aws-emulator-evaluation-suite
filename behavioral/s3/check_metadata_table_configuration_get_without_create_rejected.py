"""metadata-table-configuration-get-without-create-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "metadata-table-configuration-get-without-create-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetBucketMetadataConfiguration on a bucket that never had one fails with
    MetadataConfigurationNotFound and its exact message instead of an empty 200, and succeeds once a
    configuration is created and its journal table is ACTIVE."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    ctx.on_cleanup(lambda: _delete_metadata_tables(ctx, bucket))

    code, message = _error(lambda: s3.get_bucket_metadata_configuration(Bucket=bucket))
    assert code == "MetadataConfigurationNotFound", f"expected MetadataConfigurationNotFound, got {code}"
    assert message == "The metadata configuration was not found", message

    # Positive control: after actually creating a configuration, Get succeeds and reflects it.
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

    journal = _poll_journal_until(s3, bucket, {"ACTIVE", "FAILED"}, timeout_s=180.0, interval_s=5.0)
    assert journal["TableStatus"] == "ACTIVE", (
        f"journal table reached FAILED instead of ACTIVE: {journal.get('Error')}"
    )
    assert journal["TableName"], "ACTIVE journal table result carried no TableName"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("s3meta-src-")
    kwargs = {"Bucket": name}
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


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_journal_until(s3, bucket: str, terminal_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = s3.get_bucket_metadata_configuration(Bucket=bucket)
        assert "GetBucketMetadataConfigurationResult" in resp, sorted(resp.keys())
        result_wrapper = resp["GetBucketMetadataConfigurationResult"]
        last = result_wrapper["MetadataConfigurationResult"]["JournalTableConfigurationResult"]
        if last["TableStatus"] in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"status never reached {terminal_statuses}; last response={last}")


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
