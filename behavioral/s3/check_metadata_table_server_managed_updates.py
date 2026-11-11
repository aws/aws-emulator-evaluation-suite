"""metadata-table-server-managed-updates."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metadata-table-server-managed-updates"
GROUP = "server-side"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each UpdateBucketMetadata*TableConfiguration call changes only its own sub-resource:
    GetBucketMetadataConfiguration shows the new value while sibling sub-resources set by earlier
    calls stay intact."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    bucket = _create_bucket(ctx)
    ctx.on_cleanup(lambda: _delete_metadata_tables(ctx, bucket))
    account_id = sts.get_caller_identity()["Account"]

    initial_config = {
        "JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}},
        "InventoryTableConfiguration": {"ConfigurationState": "DISABLED"},
    }
    try:
        s3.create_bucket_metadata_configuration(Bucket=bucket, MetadataConfiguration=initial_config)
    except ClientError as exc:
        raise AssertionError(
            f"prerequisite S3 Metadata (table buckets) unavailable in this account/region: {_error_code(exc)}"
        )
    ctx.on_cleanup(lambda: _best_effort(lambda: s3.delete_bucket_metadata_configuration(Bucket=bucket)))

    # GetBucketMetadataConfiguration is eventually consistent after creation: the tables are
    # provisioned asynchronously, so reads can 404 for over a minute.
    baseline = _poll_until_available(lambda: _get_metadata_result(s3, bucket), timeout_s=300, interval_s=5.0)
    baseline_journal_expiration = baseline["JournalTableConfigurationResult"]["RecordExpiration"]["Expiration"]
    assert baseline_journal_expiration == "DISABLED", (
        f"expected freshly created journal table RecordExpiration DISABLED, got {baseline_journal_expiration!r}"
    )
    baseline_inventory_state = baseline["InventoryTableConfigurationResult"]["ConfigurationState"]
    assert baseline_inventory_state == "DISABLED", (
        f"expected freshly created inventory table ConfigurationState DISABLED, got {baseline_inventory_state!r}"
    )

    # While the journal table is still CREATING, Update*JournalTableConfiguration fails with
    # InvalidRequest, so wait for ACTIVE first.
    baseline = _poll_until(
        lambda: _get_metadata_result(s3, bucket),
        lambda r: r["JournalTableConfigurationResult"].get("TableStatus") == "ACTIVE",
        timeout_s=300,
        interval_s=5.0,
    )

    s3.update_bucket_metadata_journal_table_configuration(
        Bucket=bucket,
        JournalTableConfiguration={"RecordExpiration": {"Expiration": "ENABLED", "Days": 7}},
    )
    after_journal = _poll_until(
        lambda: _get_metadata_result(s3, bucket),
        lambda r: r["JournalTableConfigurationResult"]["RecordExpiration"]["Expiration"] == "ENABLED",
        timeout_s=30,
    )
    journal_result = after_journal["JournalTableConfigurationResult"]
    assert journal_result["RecordExpiration"]["Days"] == 7, (
        f"expected updated journal RecordExpiration.Days == 7, got {journal_result['RecordExpiration'].get('Days')!r}"
    )
    journal_status = journal_result.get("TableStatus")
    assert journal_status != "FAILED", f"expected journal TableStatus not FAILED after update, got {journal_status!r}"
    # the untouched inventory sub-resource must still read back exactly as configured.
    inventory_after_journal_update = after_journal["InventoryTableConfigurationResult"]["ConfigurationState"]
    assert inventory_after_journal_update == "DISABLED", (
        "journal update must not clobber the untouched inventory sub-resource: expected "
        f"ConfigurationState DISABLED, got {inventory_after_journal_update!r}"
    )

    s3.update_bucket_metadata_inventory_table_configuration(
        Bucket=bucket, InventoryTableConfiguration={"ConfigurationState": "ENABLED"}
    )
    after_inventory = _poll_until(
        lambda: _get_metadata_result(s3, bucket),
        lambda r: r["InventoryTableConfigurationResult"]["ConfigurationState"] == "ENABLED",
        timeout_s=60,
    )
    inv_result = after_inventory["InventoryTableConfigurationResult"]
    inventory_status = inv_result.get("TableStatus")
    assert inventory_status != "FAILED", f"expected inventory TableStatus not FAILED after update, got {inventory_status!r}"
    inventory_table_name = inv_result.get("TableName")
    assert inventory_table_name, f"expected a non-empty TableName for the enabled live inventory table, got {inventory_table_name!r}"
    # the journal sub-resource set a moment ago must remain intact: enabling inventory must
    # not have reset or corrupted the sibling journal configuration.
    still_journal = after_inventory["JournalTableConfigurationResult"]["RecordExpiration"]
    assert still_journal["Expiration"] == "ENABLED" and still_journal["Days"] == 7, (
        "inventory update must not clobber the sibling journal sub-resource: expected "
        f"Expiration ENABLED / Days 7, got {still_journal!r}"
    )

    role_name = ctx.unique_name("sim2real-s3meta-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "metadata.s3.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))
    read_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="read-annotations", PolicyDocument=json.dumps(read_policy))
    ctx.on_cleanup(
        lambda: _best_effort(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="read-annotations"))
    )

    def _enable_annotation() -> None:
        s3.update_bucket_metadata_annotation_table_configuration(
            Bucket=bucket,
            AnnotationTableConfiguration={"ConfigurationState": "ENABLED", "Role": role_arn},
        )

    # IAM role trust policy propagation is eventually consistent -- retry through AccessDenied.
    _retry_until_success(_enable_annotation, timeout_s=90, interval_s=5)

    after_annotation = _poll_until(
        lambda: _get_metadata_result(s3, bucket),
        lambda r: "AnnotationTableConfigurationResult" in r,
        timeout_s=60,
    )
    ann_result = after_annotation["AnnotationTableConfigurationResult"]
    assert ann_result["ConfigurationState"] == "ENABLED", (
        f"expected annotation ConfigurationState ENABLED after update, got {ann_result['ConfigurationState']!r}"
    )
    assert ann_result["Role"] == role_arn, f"expected annotation Role {role_arn!r}, got {ann_result['Role']!r}"

    # the two earlier updates (journal, inventory) must still be intact after the third
    # server-managed mutation -- no intermediate-state corruption across the three sub-resources.
    final_journal = after_annotation["JournalTableConfigurationResult"]["RecordExpiration"]
    assert final_journal["Expiration"] == "ENABLED" and final_journal["Days"] == 7, (
        "annotation update must not clobber the journal sub-resource: expected Expiration ENABLED / "
        f"Days 7, got {final_journal!r}"
    )
    final_inventory = after_annotation["InventoryTableConfigurationResult"]["ConfigurationState"]
    assert final_inventory == "ENABLED", (
        f"annotation update must not clobber the inventory sub-resource: expected ConfigurationState ENABLED, got {final_inventory!r}"
    )


def _create_bucket(ctx, **extra: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-s3meta-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    kwargs.update(extra)
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _best_effort(lambda: s3.delete_bucket(Bucket=name)))
    return name


def _get_metadata_result(s3, bucket: str) -> dict[str, Any]:
    # Like the V1 GetBucketMetadataTableConfiguration API, the response is wrapped in an outer
    # element named after the operation itself before the actual MetadataConfigurationResult body.
    return s3.get_bucket_metadata_configuration(Bucket=bucket)["GetBucketMetadataConfigurationResult"][
        "MetadataConfigurationResult"
    ]


def _error_code(exc: ClientError) -> str | None:
    return exc.response.get("Error", {}).get("Code")


def _best_effort(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "MetadataConfigurationNotFound",
            "NoSuchBucket",
            "NoSuchEntity",
        ):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _poll_until_available(probe: Callable[[], Any], *, timeout_s: float, interval_s: float = 3.0) -> Any:
    """Like _poll_until, but treats a ClientError from the probe itself (e.g. the metadata
    configuration not yet being readable right after creation) as "not ready yet" and retries."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return probe()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"metadata configuration never became readable within {timeout_s}s: {last_exc}")


def _retry_until_success(fn: Callable[[], Any], *, timeout_s: float, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation kept failing for {timeout_s}s: {last_exc}")


def _delete_metadata_tables(ctx, bucket: str) -> None:
    """Delete the journal/inventory tables and namespace the metadata configuration leaves in the
    account's AWS-managed table bucket; deleting the configuration or bucket keeps them, and they
    bill. Only an already-absent table or namespace is tolerated."""
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
