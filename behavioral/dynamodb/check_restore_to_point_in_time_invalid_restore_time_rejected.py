"""restore-to-point-in-time-invalid-restore-time-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-to-point-in-time-invalid-restore-time-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreTableToPointInTime with a restore time outside the PITR window returns
    InvalidRestoreTimeException and leaves no target table, while a restore to the latest
    restorable time on the same source succeeds (positive control)."""
    start = time.monotonic()
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-restoretime-")
    good_target_name = ctx.unique_name("sim2real-restoredok-")
    bad_target_name = ctx.unique_name("sim2real-restoredtgt-")

    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ddb, table_name)

    # A table's continuous backups take a moment to finish being provisioned after creation;
    # an UpdateContinuousBackups issued too soon is transiently rejected with
    # ContinuousBackupsUnavailableException ("Backups are being enabled for this table...").
    # Retry for a bounded time instead of treating that as a hard failure.
    _enable_pitr_with_retry(ddb, table_name)

    # Positive control: a restore to the latest restorable time IS inside the window and
    # must succeed. Without this, the rejection below is indistinguishable from a target
    # that refuses every RestoreTableToPointInTime call regardless of the time given.
    # LatestRestorableDateTime can lag briefly behind PITR turning ENABLED; retry for a
    # bounded time rather than treating that transient state as a hard failure.
    good_resp = _restore_with_retry(ddb, table_name, good_target_name)
    assert good_resp["TableDescription"]["TableName"] == good_target_name, (
        f"positive-control restore did not create {good_target_name}"
    )
    # DynamoDB's TagResource on a table still CREATING from a restore 404s for well over 20s, so
    # the restored table stays untagged and the cleanup below deletes it by name.
    ctx.on_cleanup(lambda: _delete_table_best_effort(ddb, good_target_name, start + 270.0))

    # A restore time long before the table existed is outside the restorable
    # window and must be rejected.
    ancient_time = datetime(2000, 1, 1, tzinfo=timezone.utc)

    def _restore():
        return ddb.restore_table_to_point_in_time(
            SourceTableName=table_name,
            TargetTableName=bad_target_name,
            RestoreDateTime=ancient_time,
        )

    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, bad_target_name))

    code, _message = _error(_restore)
    assert code == "InvalidRestoreTimeException", f"expected InvalidRestoreTimeException, got {code}"
    # message varies: it embeds the live EarliestRestorableDateTime and LatestRestorableDateTime,
    # which AWS computes at call time to the second and the check cannot observe atomically.

    # The forbidden effect must not have happened: no target table was created.
    not_found, not_found_message = _error(lambda: ddb.describe_table(TableName=bad_target_name))
    assert not_found == "ResourceNotFoundException", (
        f"rejected restore must not leave behind a target table, describe_table returned {not_found!r}"
    )
    expected_not_found = f"Requested resource not found: Table: {bad_target_name} not found"
    assert not_found_message == expected_not_found, f"unexpected message {not_found_message!r}"


# ===== helpers =====
def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _wait_table_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} did not become ACTIVE within {timeout_s}s")


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


def _restore_with_retry(ddb, source_name, target_name, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ddb.restore_table_to_point_in_time(
                SourceTableName=source_name,
                TargetTableName=target_name,
                UseLatestRestorableTime=True,
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("InvalidRestoreTimeException", "PointInTimeRecoveryUnavailableException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_table_if_exists(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_table_best_effort(ddb, table_name, deadline):
    """Cleanup of the positive-control's restored table: it can still be CREATING when the check
    body finishes, and waiting all the way to ACTIVE has been observed to outrun even the harness's
    300s hard budget. Retry deletion for a bounded time, then leak loudly rather than hang the check
    or fail assertions that already passed on a slow-but-correct target."""
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise RuntimeError(f"table {table_name!r} not deleted: {code}") from err
            time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
