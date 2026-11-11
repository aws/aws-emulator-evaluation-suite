"""export-conflict-duplicate-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-conflict-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Replaying an ExportTableToPointInTime ClientToken with identical parameters returns the
    original export; reusing it with a different ExportFormat fails with ExportConflictException
    and the original export remains tracked."""
    ddb = ctx.client("dynamodb")

    table_name = ctx.unique_name("sim2real-behav-tbl-")
    table_arn = ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_status(ctx, table_name, "ACTIVE")
    _wait_continuous_backups_ready(ctx, table_name)

    ddb.update_continuous_backups(
        TableName=table_name,
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
    )
    _wait_pitr_status(ctx, table_name, "ENABLED")

    bucket_name = ctx.unique_name("sim2real-behav-exp-")
    _create_bucket(ctx, bucket_name)

    # PITR reports ENABLED before a restorable point exists; an earlier ExportTime raises
    # InvalidExportTimeException, so export at the reported LatestRestorableDateTime.
    export_time = _wait_for_restorable_time(ctx, table_name)

    client_token = str(uuid.uuid4())
    first = ddb.export_table_to_point_in_time(
        TableArn=table_arn, S3Bucket=bucket_name, ExportTime=export_time, ClientToken=client_token
    )["ExportDescription"]
    assert first["ExportStatus"] == "IN_PROGRESS", f"expected IN_PROGRESS, got {first['ExportStatus']}"
    first_export_arn = first["ExportArn"]

    # Positive control: an identical replay returns the original export, not a conflict.
    replay = ddb.export_table_to_point_in_time(
        TableArn=table_arn, S3Bucket=bucket_name, ExportTime=export_time, ClientToken=client_token
    )["ExportDescription"]
    assert replay["ExportArn"] == first_export_arn, (
        f"expected the identical-duplicate call to replay the original export "
        f"{first_export_arn}, got a different one: {replay['ExportArn']}"
    )

    code, message = _error(
        lambda: ddb.export_table_to_point_in_time(
            TableArn=table_arn,
            S3Bucket=bucket_name,
            ExportTime=export_time,
            ClientToken=client_token,
            ExportFormat="ION",
        )
    )
    assert code == "ExportConflictException", f"expected ExportConflictException, got {code}"
    expected_message = "Export conflict: Duplicate request detected with conflicting parameters"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    desc = ddb.describe_export(ExportArn=first_export_arn)["ExportDescription"]
    assert desc["ExportStatus"] in ("IN_PROGRESS", "COMPLETED"), (
        f"expected IN_PROGRESS or COMPLETED, got {desc['ExportStatus']}"
    )
    assert desc["ExportArn"] == first_export_arn, (
        f"describe_export returned a different ARN: expected {first_export_arn}, got {desc['ExportArn']}"
    )


def _error(fn):
    """Return fn()'s error code and message; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_bucket(s3, bucket_name):
    # DeleteBucket fails on a non-empty bucket, and the export writes its data here.
    while True:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        if not objs:
            break
        failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _create_bucket(ctx, bucket_name):
    s3 = ctx.client("s3")
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket_name))


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


def _wait_for_restorable_time(ctx, table_name, timeout_s=120, interval_s=3):
    # LatestRestorableDateTime appears only after the first restorable point, which lags
    # PointInTimeRecoveryStatus=ENABLED.
    import time

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



def _wait_continuous_backups_ready(ctx, table_name, timeout_s=180, interval_s=3):
    # Right after ACTIVE, UpdateContinuousBackups can raise ContinuousBackupsUnavailableException
    # while backups are still being enabled for the table.
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
