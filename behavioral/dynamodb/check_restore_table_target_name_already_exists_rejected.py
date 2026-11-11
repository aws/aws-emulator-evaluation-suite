"""restore-table-target-name-already-exists-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-table-target-name-already-exists-rejected"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreTableFromBackup onto a TargetTableName held by a live table is refused
    TableAlreadyExistsException and leaves that table untouched; once the occupying table is
    removed, the identical restore succeeds."""
    ddb = ctx.client("dynamodb")

    source_table = ctx.unique_name("sim2real-behav-rej-src-")
    ddb.create_table(
        TableName=source_table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, source_table))
    _poll_until(
        lambda: ddb.describe_table(TableName=source_table)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )
    # A freshly-created table's continuous backups (PITR plumbing) take a short while to
    # finish enabling; CreateBackup fails with ContinuousBackupsUnavailableException until
    # that's done, which is unrelated to the TableAlreadyExistsException this check targets.
    _poll_until(
        lambda: ddb.describe_continuous_backups(TableName=source_table)[
            "ContinuousBackupsDescription"
        ]["ContinuousBackupsStatus"],
        lambda status: status == "ENABLED",
        timeout_s=120,
        interval_s=3,
    )

    backup_arn = ddb.create_backup(
        TableName=source_table, BackupName=ctx.unique_name("sim2real-behav-rej-bk-")
    )["BackupDetails"]["BackupArn"]
    ctx.on_cleanup(lambda: _safe_delete_backup(ddb, backup_arn))
    _poll_until(
        lambda: ddb.describe_backup(BackupArn=backup_arn)["BackupDescription"]["BackupDetails"][
            "BackupStatus"
        ],
        lambda status: status == "AVAILABLE",
        timeout_s=180,
        interval_s=3,
    )

    # A second, already-existing, live table occupies the name we will (illegitimately) ask
    # RestoreTableFromBackup to target.
    occupied_table = ctx.unique_name("sim2real-behav-rej-occupied-")
    ddb.create_table(
        TableName=occupied_table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, occupied_table))
    _poll_until(
        lambda: ddb.describe_table(TableName=occupied_table)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )

    code, message = _error(
        lambda: ddb.restore_table_from_backup(
            TargetTableName=occupied_table, BackupArn=backup_arn
        )
    )
    assert code == "TableAlreadyExistsException", (
        f"expected TableAlreadyExistsException, got {code!r}"
    )
    expected = f"Table already exists: {occupied_table}"
    assert message == expected, f"unexpected message {message!r}"

    # The occupied table must be completely unaffected by the rejected restore attempt.
    still_active = ddb.describe_table(TableName=occupied_table)["Table"]["TableStatus"]
    assert still_active == "ACTIVE", (
        f"expected the occupied table to remain ACTIVE after the rejected restore, "
        f"got {still_active!r}"
    )

    # Remove the obstruction and demand the identical call now succeeds. A target that
    # rejects RestoreTableFromBackup unconditionally with this code -- rather than only
    # when the name collides -- passes every assertion above and must fail here.
    ddb.delete_table(TableName=occupied_table)
    _poll_until(
        lambda: _table_status_or_gone(ddb, occupied_table),
        lambda status: status is None,
        timeout_s=120,
        interval_s=3,
    )
    _retry_restore_until_accepted(
        ddb, occupied_table, backup_arn, timeout_s=60, interval_s=3
    )
    restored_status = _poll_until(
        lambda: ddb.describe_table(TableName=occupied_table)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=600,
        interval_s=5,
    )
    assert restored_status == "ACTIVE", (
        f"expected the identical restore to succeed once the target name was free, "
        f"got {restored_status!r}"
    )


# ===== helpers =====

def _error(fn: Callable[[], Any]) -> tuple[str | None, str | None]:
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _table_status_or_gone(ddb: Any, table_name: str) -> str | None:
    try:
        return ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _retry_restore_until_accepted(
    ddb: Any, table_name: str, backup_arn: str, *, timeout_s: float, interval_s: float
) -> None:
    """DynamoDB may briefly still consider a just-deleted name reserved; retry the
    restore call itself (not just the readiness poll) until it is accepted."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.restore_table_from_backup(TargetTableName=table_name, BackupArn=backup_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TableAlreadyExistsException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"the identical restore was still rejected as TableAlreadyExistsException "
                    f"{timeout_s}s after the occupying table was deleted"
                )
            time.sleep(interval_s)


def _safe_delete_table(ddb: Any, table_name: str) -> None:
    # A table still transitioning (e.g. mid-restore, still CREATING) refuses DeleteTable with
    # ResourceInUseException: retried every 2 s for up to 300 s, within the suite's cleanup
    # budget. A table already gone is fine; any other error raises.
    deadline = time.monotonic() + 300
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe_delete_backup(ddb: Any, backup_arn: str) -> None:
    try:
        ddb.delete_backup(BackupArn=backup_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "BackupNotFoundException":
            raise


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
