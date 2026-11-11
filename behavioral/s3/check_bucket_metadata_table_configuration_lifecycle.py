"""bucket-metadata-table-configuration-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-metadata-table-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBucketMetadataConfiguration is reflected by Get with the journal table's RecordExpiration
    DISABLED and TableStatus CREATING or ACTIVE, and after DeleteBucketMetadataConfiguration Get fails
    with MetadataConfigurationNotFound."""
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-metatbl-")
    _create_bucket(s3, ctx, bucket)
    # The table bucket and namespace S3 reports for the configuration, read before it is deleted.
    destination = {}
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    ctx.on_cleanup(lambda: _delete_metadata_tables(ctx, destination))
    ctx.on_cleanup(lambda: _safe(s3.delete_bucket_metadata_configuration, Bucket=bucket))

    # S3 rejects the V1 *BucketMetadataTableConfiguration operations with V1APIsNotAllowed.
    metadata_cfg = {"JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}}}
    try:
        s3.create_bucket_metadata_configuration(Bucket=bucket, MetadataConfiguration=metadata_cfg)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError("insufficient permissions to create a metadata table configuration") from exc
        raise
    destination["created"] = True

    def _read():
        resp = s3.get_bucket_metadata_configuration(Bucket=bucket)
        destination.update(
            resp["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]["DestinationResult"])
        return resp

    got = _poll_until(
        _read,
        lambda r: "JournalTableConfigurationResult" in r["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"],
        timeout_s=180,
        interval_s=5,
    )
    result = got["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]
    journal = result["JournalTableConfigurationResult"]
    assert journal["RecordExpiration"]["Expiration"] == "DISABLED"
    assert journal["TableStatus"] in ("CREATING", "ACTIVE"), journal["TableStatus"]

    s3.delete_bucket_metadata_configuration(Bucket=bucket)

    # Retried because teardown is not always instantaneous; only the not-found code counts.
    deadline = time.monotonic() + 240
    code = None
    gone = False
    while time.monotonic() < deadline:
        try:
            s3.get_bucket_metadata_configuration(Bucket=bucket)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "MetadataConfigurationNotFound":
                gone = True
                break
        else:
            code = None
        time.sleep(5)
    assert gone, (
        f"expected MetadataConfigurationNotFound after delete, got error code {code!r}"
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last result: {last!r}")


def _delete_metadata_tables(ctx, destination: dict) -> None:
    """Delete the journal and inventory tables, and their namespace, that the bucket's metadata
    configuration leaves in the AWS-managed table bucket S3 reported: deleting the configuration
    or the bucket keeps them, and they bill. Only an already-absent table or namespace is
    tolerated; a created configuration whose destination was never read raises."""
    from botocore.exceptions import ClientError

    if not destination.get("created"):
        return
    if "TableBucketArn" not in destination or "TableNamespace" not in destination:
        raise RuntimeError("the metadata configuration's table destination was never read; "
                           "its journal and inventory tables may remain")
    tables = ctx.client("s3tables")
    arn = destination["TableBucketArn"]
    namespace = destination["TableNamespace"]
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

