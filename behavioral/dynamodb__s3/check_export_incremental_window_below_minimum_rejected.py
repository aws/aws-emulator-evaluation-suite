"""export-incremental-window-below-minimum-rejected."""
from __future__ import annotations

import time
from datetime import timedelta

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-incremental-window-below-minimum-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb", "s3"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ExportTableToPointInTime INCREMENTAL_EXPORT rejects a sub-15-minute window with
    InvalidExportTimeException, while a 16-minute window is accepted and is the table's
    only export.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html
    """
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")

    table_name = ctx.unique_name("sim2real-behav-tbl-")
    table_arn = ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ddb, table_name)
    _enable_pitr_with_retry(ddb, table_name)
    _wait_pitr_status(ddb, table_name, "ENABLED")
    # The window quota (15 min - 24 h) is checked against the table's actual restorable
    # range, so a window test needs that range to already span more than 15 minutes.
    earliest, latest = _wait_for_restorable_spread(ddb, table_name, timedelta(minutes=17))

    bucket_name = ctx.unique_name("sim2real-behav-exp-").lower()
    _create_bucket(ctx, s3, bucket_name)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))

    valid_from, valid_to = earliest, earliest + timedelta(minutes=16)
    positive = ddb.export_table_to_point_in_time(
        TableArn=table_arn,
        S3Bucket=bucket_name,
        ExportType="INCREMENTAL_EXPORT",
        IncrementalExportSpecification={"ExportFromTime": valid_from, "ExportToTime": valid_to},
    )["ExportDescription"]
    assert positive["ExportStatus"] in ("IN_PROGRESS", "COMPLETED"), (
        f"expected the 16-minute window to be accepted, got {positive['ExportStatus']!r}"
    )
    positive_export_arn = positive["ExportArn"]

    narrow_from, narrow_to = latest - timedelta(minutes=1), latest

    def _export():
        ddb.export_table_to_point_in_time(
            TableArn=table_arn,
            S3Bucket=bucket_name,
            ExportType="INCREMENTAL_EXPORT",
            IncrementalExportSpecification={"ExportFromTime": narrow_from, "ExportToTime": narrow_to},
        )

    code, message = _error_code_and_message(_export)
    assert code == "InvalidExportTimeException", f"expected InvalidExportTimeException, got {code}"
    assert message == (
        "Difference between export period from time and export period to time is less than 15 minutes"
    ), f"unexpected message {message!r}"

    exports = ddb.list_exports(TableArn=table_arn).get("ExportSummaries", [])
    export_arns = [e["ExportArn"] for e in exports]
    assert export_arns == [positive_export_arn], (
        f"expected only the positive-control export {positive_export_arn!r}, found {export_arns!r}"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _create_bucket(ctx, s3, bucket_name):
    # S3 CreateBucket rejects an explicit LocationConstraint naming us-east-1, its own default.
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


def _wait_table_active(ddb, table_name, timeout_s=180, interval_s=3):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError("table did not reach ACTIVE")


def _enable_pitr_with_retry(ddb, table_name, timeout_s=120, interval_s=3):
    # A table's continuous backups take a moment to provision after creation; an
    # UpdateContinuousBackups issued too soon is transiently rejected.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_continuous_backups(
                TableName=table_name,
                PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
            )
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ContinuousBackupsUnavailableException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _wait_pitr_status(ddb, table_name, target, timeout_s=120, interval_s=2):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_continuous_backups(TableName=table_name)["ContinuousBackupsDescription"]
        status = desc["PointInTimeRecoveryDescription"].get("PointInTimeRecoveryStatus")
        if status == target:
            return
        time.sleep(interval_s)
    raise AssertionError(f"PITR did not reach {target}")


def _wait_for_restorable_spread(ddb, table_name, min_spread, timeout_s=1500, interval_s=5):
    """Poll until (latest - earliest restorable) clears ``min_spread``; return the fresh pair.

    LatestRestorableDateTime does not start advancing immediately after PITR turns ENABLED,
    so the spread only grows once the underlying continuous-backups stream has warmed up.
    """
    deadline = time.monotonic() + timeout_s
    last_seen = None
    while time.monotonic() < deadline:
        desc = ddb.describe_continuous_backups(TableName=table_name)["ContinuousBackupsDescription"]
        pitr = desc["PointInTimeRecoveryDescription"]
        earliest, latest = pitr.get("EarliestRestorableDateTime"), pitr.get("LatestRestorableDateTime")
        last_seen = (earliest, latest)
        if earliest is not None and latest is not None and latest - earliest >= min_spread:
            return earliest, latest
        time.sleep(interval_s)
    raise AssertionError(f"restorable spread never reached {min_spread}, last seen {last_seen!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
