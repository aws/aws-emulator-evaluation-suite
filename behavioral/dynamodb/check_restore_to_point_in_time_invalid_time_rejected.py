"""restore-to-point-in-time-invalid-time-rejected."""
from __future__ import annotations

import datetime as dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-to-point-in-time-invalid-time-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreTableToPointInTime with a RestoreDateTime a day before the table's creation raises
    InvalidRestoreTimeException and creates no target table, while a valid restore of the same source table is
    accepted.
    """
    ddb = ctx.client("dynamodb")
    source_name = ctx.unique_name("sim2real-behav-src-")
    ddb.create_table(
        TableName=source_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=source_name))
    created = _wait_table_status(ctx, source_name, "ACTIVE")
    creation_time = created["CreationDateTime"]

    _enable_pitr_with_retry(ddb, source_name)
    _wait_pitr_status(ctx, source_name, "ENABLED")

    # Positive control: a valid restore against this same source table must succeed. Without
    # this, a target that rejects EVERY RestoreTableToPointInTime call with
    # InvalidRestoreTimeException (valid input or not) would pass the negative assertion below
    # just as well as a target that correctly discriminates on the restore time.
    control_name = ctx.unique_name("sim2real-behav-restored-ctrl-")
    control_desc = _restore_with_retry(ddb, source_name, control_name)
    assert control_desc["TableName"] == control_name, (
        f"positive control: valid RestoreTableToPointInTime did not accept, got {control_desc}"
    )
    ctx.on_cleanup(lambda: _try_delete_table(ddb, control_name))

    target_name = ctx.unique_name("sim2real-behav-restored-")
    too_early = creation_time - dt.timedelta(days=1)

    code, _message = _error(
        lambda: ddb.restore_table_to_point_in_time(
            SourceTableName=source_name,
            TargetTableName=target_name,
            RestoreDateTime=too_early,
        )
    )
    assert code == "InvalidRestoreTimeException", f"expected InvalidRestoreTimeException, got {code}"
    # message varies: it embeds the live EarliestRestorableDateTime and LatestRestorableDateTime,
    # which AWS computes at call time to the second and the check cannot observe atomically.

    # The forbidden effect (target table creation) must not have happened.
    table_names = ddb.list_tables()["TableNames"]
    assert target_name not in table_names, "target table should not exist after rejected restore"
    not_found, not_found_message = _error(lambda: ddb.describe_table(TableName=target_name))
    assert not_found == "ResourceNotFoundException", (
        f"target table should not exist after rejected restore, describe_table gave {not_found!r}"
    )
    expected_not_found = f"Requested resource not found: Table: {target_name} not found"
    assert not_found_message == expected_not_found, f"unexpected message {not_found_message!r}"


def _error(fn):
    """Return (code, message) of the ClientError ``fn`` raises; an accepted call fails the check."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _enable_pitr_with_retry(ddb, table_name, timeout_s=120, interval_s=3):
    """A just-created table has continuous backups enabling in the background; an
    UpdateContinuousBackups issued too soon is rejected until that settles — retry for a
    bounded time rather than treating it as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_continuous_backups(
                TableName=table_name,
                PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
            )
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ContinuousBackupsUnavailableException" or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _restore_with_retry(ddb, source_name, target_name, timeout_s=90, interval_s=3):
    """UseLatestRestorableTime can trail table/PITR creation by a few seconds; retry the
    transient not-yet-available codes for a bounded time rather than treating them as a hard
    failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ddb.restore_table_to_point_in_time(
                SourceTableName=source_name,
                TargetTableName=target_name,
                UseLatestRestorableTime=True,
            )["TableDescription"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("PointInTimeRecoveryUnavailableException", "InvalidRestoreTimeException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _try_delete_table(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "ResourceInUseException"):
            raise


def _wait_table_status(ctx, table_name, target_status, timeout_s=180, interval_s=3):
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    last = None
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        last = desc["TableStatus"]
        if last == target_status:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never reached {target_status}, last={last}")


def _wait_pitr_status(ctx, table_name, target_status, timeout_s=120, interval_s=3):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
