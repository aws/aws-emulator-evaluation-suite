"""export-to-point-in-time-invalid-time-rejected."""
from __future__ import annotations

import datetime as dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-to-point-in-time-invalid-time-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ExportTableToPointInTime with an ExportTime in the future raises InvalidExportTimeException ("Export Time is
    invalid") and registers no export beyond the accepted export at a valid time.
    """
    ddb = ctx.client("dynamodb")

    table_name = ctx.unique_name("sim2real-behav-tbl-")
    table_arn = ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_status(ctx, table_name, "ACTIVE")
    _wait_continuous_backups_ready(ctx, table_name)

    ddb.update_continuous_backups(
        TableName=table_name,
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
    )
    _wait_pitr_status(ctx, table_name, "ENABLED")
    # PointInTimeRecoveryStatus flips to ENABLED before the underlying continuous-backups
    # stream has an actual restorable point recorded; a positive-control ExportTime picked
    # relative to "now" right after enablement can land before that first restorable point
    # and gets rejected with InvalidExportTimeException for an unrelated reason. Poll for a
    # real, AWS-reported LatestRestorableDateTime and export to that instant instead.
    restorable_time = _wait_for_restorable_time(ctx, table_name)

    bucket_name = ctx.unique_name("sim2real-behav-exp-")
    _create_bucket(ctx, bucket_name)

    positive = ddb.export_table_to_point_in_time(
        TableArn=table_arn, S3Bucket=bucket_name, ExportTime=restorable_time
    )["ExportDescription"]
    assert positive["ExportStatus"] in ("IN_PROGRESS", "COMPLETED"), positive
    positive_export_arn = positive["ExportArn"]

    future_time = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
    code, message = _error_code_and_message(
        lambda: ddb.export_table_to_point_in_time(
            TableArn=table_arn, S3Bucket=bucket_name, ExportTime=future_time
        )
    )
    assert code == "InvalidExportTimeException", f"expected InvalidExportTimeException, got {code}"
    assert message == "Export Time is invalid", f"expected message 'Export Time is invalid', got {message!r}"

    exports = ddb.list_exports(TableArn=table_arn).get("ExportSummaries", [])
    export_arns = [e["ExportArn"] for e in exports]
    assert export_arns == [positive_export_arn], (
        f"expected only the positive-control export {positive_export_arn}, found {export_arns}"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, bucket_name):
    s3 = ctx.client("s3")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))


def _empty_and_delete_bucket(s3, bucket_name):
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _wait_for_restorable_time(ctx, table_name, timeout_s=120, interval_s=3):
    ddb = ctx.client("dynamodb")
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


def _wait_table_status(ctx, table_name, target_status, timeout_s=180, interval_s=3):
    import time

    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        last = desc["TableStatus"]
        if last == target_status:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never reached {target_status}, last={last}")


def _wait_pitr_status(ctx, table_name, target_status, timeout_s=120, interval_s=3):
    import time

    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = ddb.describe_continuous_backups(TableName=table_name)["ContinuousBackupsDescription"]
        last = desc["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]
        if last == target_status:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"PITR on {table_name} never reached {target_status}, last={last}")


def _wait_continuous_backups_ready(ctx, table_name, timeout_s=180, interval_s=3):
    # Immediately after a table reaches ACTIVE, DynamoDB is still provisioning the
    # continuous-backups infrastructure that UpdateContinuousBackups depends on; calling
    # it too early raises ContinuousBackupsUnavailableException ("Backups are being
    # enabled for this table"). Poll until the infra itself is ready first.
    import time

    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = ddb.describe_continuous_backups(TableName=table_name)["ContinuousBackupsDescription"]
        last = desc["ContinuousBackupsStatus"]
        if last == "ENABLED":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"continuous backups for {table_name} never became ENABLED, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
