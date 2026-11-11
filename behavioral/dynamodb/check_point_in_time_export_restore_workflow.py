"""point-in-time-export-restore-workflow."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "point-in-time-export-restore-workflow"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With continuous backups enabled, ExportTableToPointInTime completes and is
    listed, and RestoreTableToPointInTime materializes a new active table."""
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")

    table_name = ctx.unique_name("sim2real-behav-pitr-tbl-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, table_name))
    _wait_table_active(ddb, table_name)
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    # Write the item BEFORE continuous backups are enabled, not after. Measured on real AWS:
    # PointInTimeRecoveryStatus flips to ENABLED long before LatestRestorableDateTime catches up
    # to wall-clock time -- on a table whose backups were only just turned on, that lag exceeded
    # 300s in practice. UseLatestRestorableTime then targets a point BEFORE anything written
    # after enablement, so such a write can silently vanish from the restore. An item already
    # present when PITR starts protecting the table has no such race: it is covered from
    # EarliestRestorableDateTime onward, which is always <= whatever LatestRestorableDateTime
    # is when the restore fires.
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "exp-1"}, "data": {"S": "pitr-export-data"}})

    _update_continuous_backups_with_retry(ddb, table_name)
    _poll_until(
        lambda: ddb.describe_continuous_backups(TableName=table_name)["ContinuousBackupsDescription"][
            "PointInTimeRecoveryDescription"
        ]["PointInTimeRecoveryStatus"],
        lambda s: s == "ENABLED",
        timeout_s=120,
        interval_s=1,
    )

    bucket = ctx.unique_name("sim2real-behav-pitr-bucket-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    export_resp = ddb.export_table_to_point_in_time(TableArn=table_arn, S3Bucket=bucket, ExportFormat="DYNAMODB_JSON")
    export_arn = export_resp["ExportDescription"]["ExportArn"]
    assert export_resp["ExportDescription"]["ExportStatus"] == "IN_PROGRESS", (
        f"expected export to start IN_PROGRESS, got {export_resp['ExportDescription']['ExportStatus']!r}"
    )
    # Exports are not independently deletable; the S3 bucket cleanup removes the artifacts.

    # The export and a point-in-time restore are independent async control-plane
    # operations against the same (continuous-backups-enabled) source table --
    # waiting for the export to fully COMPLETE before even starting the restore
    # needlessly serializes two waits that can run concurrently, and doing so
    # risks exceeding the check's overall time budget. Kick the restore off now
    # and poll both to completion together.
    target_name = ctx.unique_name("sim2real-behav-pitr-dst-")
    restored = ddb.restore_table_to_point_in_time(
        SourceTableName=table_name,
        TargetTableName=target_name,
        UseLatestRestorableTime=True,
    )
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, target_name))
    assert restored["TableDescription"]["TableStatus"] in ("CREATING", "ACTIVE"), (
        f"expected restore response status in (CREATING, ACTIVE), "
        f"got {restored['TableDescription']['TableStatus']!r}"
    )
    assert restored["TableDescription"]["RestoreSummary"]["SourceTableArn"] == table_arn, (
        f"expected RestoreSummary.SourceTableArn {table_arn!r}, "
        f"got {restored['TableDescription']['RestoreSummary']['SourceTableArn']!r}"
    )

    # Both ExportTableToPointInTime (which snapshots the full table to S3)
    # and RestoreTableToPointInTime (which provisions a fresh table's storage
    # partitions) are genuinely slow, multi-minute control-plane operations on
    # real AWS; 240s is frequently not enough headroom for either leg to
    # finish, so give the joint poll a longer bound.
    export_status, target_status = _poll_pair(
        lambda: ddb.describe_export(ExportArn=export_arn)["ExportDescription"]["ExportStatus"],
        lambda s: s in ("COMPLETED", "FAILED"),
        lambda: ddb.describe_table(TableName=target_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=900,
        interval_s=10,
    )
    assert export_status == "COMPLETED", f"export did not complete: {ddb.describe_export(ExportArn=export_arn)}"
    assert target_status == "ACTIVE", f"expected restored table ACTIVE, got {target_status!r}"
    # TagResource 404s on a just-restored table while it is still CREATING (the tagging
    # index has not caught up yet) -- tag only once it is confirmed ACTIVE above.
    ddb.tag_resource(
        ResourceArn=restored["TableDescription"]["TableArn"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    # RestoreTableToPointInTime reaching ACTIVE with a correct RestoreSummary is not, on its
    # own, proof that any data made it across -- a target could materialize an empty table with
    # the right metadata and still pass everything above. Read the item back through the
    # destination table's own independent GetItem to prove the restore actually carried the
    # source table's data, not just its shape.
    restored_item = ddb.get_item(TableName=target_name, Key={"pk": {"S": "exp-1"}}).get("Item")
    assert restored_item is not None, f"restored table {target_name} is missing item 'exp-1' written before restore"
    assert restored_item["data"]["S"] == "pitr-export-data", (
        f"expected restored item data 'pitr-export-data', got {restored_item['data']!r}"
    )

    listed = ddb.list_exports(TableArn=table_arn)["ExportSummaries"]
    matching = [e for e in listed if e["ExportArn"] == export_arn]
    assert len(matching) == 1, f"expected export {export_arn} in ListExports, got {listed}"
    assert matching[0]["ExportStatus"] == "COMPLETED", (
        f"expected ListExports entry for {export_arn} to show COMPLETED, got {matching[0]['ExportStatus']!r}"
    )


def _poll_pair(
    probe_a: Callable[[], Any],
    done_a: Callable[[Any], bool],
    probe_b: Callable[[], Any],
    done_b: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> tuple[Any, Any]:
    """Poll two independent conditions concurrently (interleaved in one loop)
    until BOTH are satisfied, so two unrelated async waits cost wall-clock
    ``max(time_a, time_b)`` instead of ``time_a + time_b``."""
    deadline = time.monotonic() + timeout_s
    result_a = result_b = None
    fin_a = fin_b = False
    while time.monotonic() < deadline:
        if not fin_a:
            result_a = probe_a()
            fin_a = done_a(result_a)
        if not fin_b:
            result_b = probe_b()
            fin_b = done_b(result_b)
        if fin_a and fin_b:
            return result_a, result_b
        time.sleep(interval_s)
    raise AssertionError(
        f"condition(s) not met within {timeout_s}s: a={result_a!r} (done={fin_a}), "
        f"b={result_b!r} (done={fin_b})"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _wait_table_active(ddb, table_name: str, timeout_s: float = 120) -> None:
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=1,
    )


def _update_continuous_backups_with_retry(ddb, table_name: str, *, timeout_s: float = 120, interval_s: float = 2) -> None:
    # Immediately after a table becomes ACTIVE, its continuous-backups
    # infrastructure can still be settling ("Backups are being enabled for
    # ..."), which makes UpdateContinuousBackups transiently reject with
    # ContinuousBackupsUnavailableException. Retry within a bound instead of
    # treating this as a hard failure.
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            ddb.update_continuous_backups(
                TableName=table_name,
                PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
            )
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ContinuousBackupsUnavailableException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"UpdateContinuousBackups still unavailable after {timeout_s}s: {last_err}")


def _delete_table_ignore(ddb, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _create_bucket(ctx, s3, bucket: str) -> None:
    # S3's CreateBucket rejects an explicit LocationConstraint of us-east-1 itself
    # (it is the implicit default) -- this is an API quirk, not a region pin.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if keys:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
