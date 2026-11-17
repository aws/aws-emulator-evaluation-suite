"""export-table-to-point-in-time-invalid-export-format-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-table-to-point-in-time-invalid-export-format-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb", "s3"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ExportTableToPointInTime with ExportFormat='DYNAMODB_JSON' starts an export job, while the
    same call with an ExportFormat outside the enum raises ValidationException with the exact
    message and starts no export.
    """
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")

    table_name = ctx.unique_name("sim2real-behav-expfmt-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _wait_table_active(ddb, table_name)
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    _enable_pitr(ddb, table_name)

    bucket = ctx.unique_name("sim2real-behav-expfmt-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    # Positive control: the one legal ExportFormat value starts a real export job.
    valid_resp = ddb.export_table_to_point_in_time(
        TableArn=table_arn, S3Bucket=bucket, ExportFormat="DYNAMODB_JSON"
    )["ExportDescription"]
    valid_arn = valid_resp["ExportArn"]
    assert valid_resp["ExportStatus"] in ("IN_PROGRESS", "COMPLETED"), valid_resp

    # ExportFormat outside the DYNAMODB_JSON/ION enum is refused before any job starts.
    code, message = _error(
        lambda: ddb.export_table_to_point_in_time(
            TableArn=table_arn, S3Bucket=bucket, ExportFormat="CSV"
        )
    )
    assert code == "ValidationException", f"ExportFormat='CSV' raised {code!r}, expected ValidationException"
    expected = (
        "1 validation error detected: Value 'CSV' at 'exportFormat' failed to satisfy constraint: "
        "Member must satisfy enum value set: [ION, DYNAMODB_JSON]"
    )
    assert message == expected, f"ExportFormat='CSV' message was {message!r}, expected {expected!r}"

    # Independent read: only the one real export this check started is listed for the table; the
    # refused call did not create a second one.
    listed = [e["ExportArn"] for e in ddb.list_exports(TableArn=table_arn)["ExportSummaries"]]
    assert listed == [valid_arn], (
        f"ListExports after the refusal returned {listed!r}, expected only {[valid_arn]!r}"
    )


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An accepted call raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _wait_table_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} did not become ACTIVE within {timeout_s}s")


def _enable_pitr(ddb, table_name, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ddb.update_continuous_backups(
                TableName=table_name,
                PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "ContinuousBackupsUnavailableException":
                raise
            time.sleep(interval_s)
    else:
        raise AssertionError(f"PITR enable still unavailable for {table_name} after {timeout_s}s")

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ddb.describe_continuous_backups(TableName=table_name)[
            "ContinuousBackupsDescription"
        ]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]
        if status == "ENABLED":
            return
        time.sleep(interval_s)
    raise AssertionError(f"PITR for {table_name} never reached ENABLED within {timeout_s}s")


def _delete_bucket(s3, bucket):
    try:
        while True:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            if not objs:
                break
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _safe_delete_table(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
