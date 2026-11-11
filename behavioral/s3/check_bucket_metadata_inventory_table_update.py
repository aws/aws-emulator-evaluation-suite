"""bucket-metadata-inventory-table-update."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-metadata-inventory-table-update"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After a base S3 Metadata configuration exists, UpdateBucketMetadataInventoryTableConfiguration
    enables the (auto-managed) live inventory table and GetBucketMetadataConfiguration reflects it."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-metainv-")
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

    # Real AWS rejects UpdateBucketMetadataInventoryTableConfiguration with InvalidRequest
    # ("You can't perform this operation while the journal table is being created. Wait for
    # your journal table status to transition to ACTIVE, and then try again.") while the base
    # journal table is still CREATING, so wait for it to actually reach ACTIVE (not merely be
    # present) before attempting the inventory-table update.
    before = _poll_until(
        lambda: s3.get_bucket_metadata_configuration(Bucket=bucket),
        lambda r: r["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]
        .get("JournalTableConfigurationResult", {})
        .get("TableStatus")
        == "ACTIVE",
        timeout_s=180,
        interval_s=5,
    )
    before_result = before["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]
    # A freshly created base configuration may already report a default (e.g. DISABLED)
    # inventory-table entry rather than omitting the key entirely, so only require that the
    # live inventory table isn't already enabled -- the update below is what enables it.
    before_inventory = before_result.get("InventoryTableConfigurationResult")
    assert before_inventory is None or before_inventory.get("ConfigurationState") != "ENABLED", (
        f"expected inventory table not yet ENABLED on a fresh base configuration, "
        f"got InventoryTableConfigurationResult={before_inventory!r}"
    )

    try:
        _update_inventory_table_with_retry(
            s3, bucket, {"ConfigurationState": "ENABLED"}
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError("insufficient permissions to enable a live inventory table") from exc
        raise

    after = _poll_until(
        lambda: s3.get_bucket_metadata_configuration(Bucket=bucket),
        lambda r: "InventoryTableConfigurationResult" in r["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"],
        timeout_s=60,
        interval_s=3,
    )
    after_result = after["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]
    inv = after_result["InventoryTableConfigurationResult"]
    assert inv["ConfigurationState"] == "ENABLED", (
        f"expected ConfigurationState ENABLED after the update, got {inv.get('ConfigurationState')!r}"
    )
    assert inv.get("TableStatus") in ("CREATING", "ACTIVE", None), (
        f"expected the newly-enabled inventory table to be settling (CREATING/ACTIVE/absent), "
        f"not a terminal failure state, got TableStatus={inv.get('TableStatus')!r}"
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


def _update_inventory_table_with_retry(s3, bucket, inventory_table_configuration, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            s3.update_bucket_metadata_inventory_table_configuration(
                Bucket=bucket, InventoryTableConfiguration=inventory_table_configuration
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
