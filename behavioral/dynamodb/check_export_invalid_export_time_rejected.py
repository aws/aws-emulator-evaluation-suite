"""export-invalid-export-time-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-invalid-export-time-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ExportTableToPointInTime at 2000-01-01, before the table existed, raises InvalidExportTimeException
    ("Export Time is invalid") and registers no export, while an export at LatestRestorableDateTime is accepted.
    """
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")
    table_name = ctx.unique_name("sim2real-exporttime-")

    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ddb, table_name)

    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    # A table's continuous backups take a moment to finish being provisioned after creation;
    # an UpdateContinuousBackups issued too soon is transiently rejected with
    # ContinuousBackupsUnavailableException ("Backups are being enabled for this table...").
    # Retry for a bounded time instead of treating that as a hard failure.
    _enable_pitr_with_retry(ddb, table_name)
    _wait_pitr_status(ddb, table_name, "ENABLED")

    bucket_name = ctx.unique_name("sim2real-export-bucket-").lower()
    _create_bucket(ctx, s3, bucket_name)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))

    # PointInTimeRecoveryStatus flips to ENABLED before the underlying continuous-backups
    # stream actually has a restorable point recorded; a time picked relative to "now" right
    # after enablement can land before that first restorable point and gets rejected with
    # InvalidExportTimeException for a reason unrelated to what this check means to prove.
    # Poll for the table's own reported LatestRestorableDateTime instead of guessing one.
    restorable_time = _wait_for_restorable_time(ddb, table_name)

    # Positive control: without this, "rejects an export time before the table existed" is
    # indistinguishable from "rejects every ExportTableToPointInTime call" -- the failure mode
    # a target with no export support at all would also produce.
    valid_export = ddb.export_table_to_point_in_time(
        TableArn=table_arn, S3Bucket=bucket_name, ExportTime=restorable_time
    )["ExportDescription"]
    assert valid_export["ExportStatus"] in (
        "IN_PROGRESS",
        "COMPLETED",
    ), f"expected the restorable-time export to be accepted, got {valid_export}"
    valid_export_arn = valid_export["ExportArn"]

    # A time long before the table (and its PITR window) existed is outside the
    # earliest-restorable boundary and must be rejected.
    ancient_time = datetime(2000, 1, 1, tzinfo=timezone.utc)

    def _export():
        ddb.export_table_to_point_in_time(
            TableArn=table_arn,
            S3Bucket=bucket_name,
            ExportTime=ancient_time,
        )

    code, message = _error_code_and_message(_export)
    assert code == "InvalidExportTimeException", f"expected InvalidExportTimeException, got {code}"
    assert message == "Export Time is invalid", f"expected message 'Export Time is invalid', got {message!r}"

    # Effect absent: the rejected attempt registered no export of its own -- only the
    # positive-control export shows up for the table.
    exports = ddb.list_exports(TableArn=table_arn).get("ExportSummaries", [])
    export_arns = {e["ExportArn"] for e in exports}
    assert export_arns == {
        valid_export_arn
    }, f"expected only the positive-control export {valid_export_arn}, found {export_arns}"


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected ExportTableToPointInTime to raise, it succeeded")


def _create_bucket(ctx, s3, bucket_name):
    # S3's CreateBucket rejects an explicit LocationConstraint that names us-east-1 (its own
    # default region); the literal below is an S3 API quirk, not a region pin.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )


def _empty_and_delete_bucket(s3, bucket_name):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _enable_pitr_with_retry(ddb, table_name, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_continuous_backups(
                TableName=table_name,
                PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
            )
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code != "ContinuousBackupsUnavailableException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_pitr_status(ddb, table_name, target_status, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = ddb.describe_continuous_backups(TableName=table_name)["ContinuousBackupsDescription"]
        last = desc["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]
        if last == target_status:
            return
        time.sleep(interval_s)
    raise AssertionError(f"PITR on {table_name} never reached {target_status}, last={last}")


def _wait_for_restorable_time(ddb, table_name, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = ddb.describe_continuous_backups(TableName=table_name)["ContinuousBackupsDescription"]
        pitr = desc["PointInTimeRecoveryDescription"]
        last = pitr.get("LatestRestorableDateTime")
        if last is not None:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"no LatestRestorableDateTime for {table_name} after {timeout_s}s, last={last}")


def _wait_table_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
