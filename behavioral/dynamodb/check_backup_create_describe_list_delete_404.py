"""backup-create-describe-list-delete-404."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "backup-create-describe-list-delete-404"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A table backup transitions CREATING->AVAILABLE, appears in ListBackups,
    and DescribeBackup 404s (BackupNotFoundException) once deleted."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-backup-tbl-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, table_name))
    _wait_table_active(ddb, table_name)

    backup_name = ctx.unique_name("sim2real-behav-backup-")
    created = _create_backup_with_retry(ddb, table_name, backup_name)
    backup_arn = created["BackupDetails"]["BackupArn"]
    assert created["BackupDetails"]["BackupStatus"] in ("CREATING", "AVAILABLE")
    ctx.on_cleanup(lambda: _delete_backup_ignore(ddb, backup_arn))

    status = _poll_until(
        lambda: ddb.describe_backup(BackupArn=backup_arn)["BackupDescription"]["BackupDetails"]["BackupStatus"],
        lambda s: s == "AVAILABLE",
        timeout_s=120,
        interval_s=3,
    )
    assert status == "AVAILABLE"

    listed = ddb.list_backups(TableName=table_name)["BackupSummaries"]
    matching = [b for b in listed if b["BackupArn"] == backup_arn]
    assert len(matching) == 1, f"expected backup {backup_arn} in ListBackups, got {listed}"
    assert matching[0]["BackupStatus"] == "AVAILABLE"
    assert matching[0]["TableName"] == table_name

    delete_resp = ddb.delete_backup(BackupArn=backup_arn)
    assert delete_resp["BackupDescription"]["BackupDetails"]["BackupStatus"] == "DELETED"

    def _describe_after_delete() -> tuple[str, str]:
        try:
            ddb.describe_backup(BackupArn=backup_arn)
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        return "STILL_PRESENT", ""

    not_found_msg = f"Backup not found: {backup_arn}"
    final = _poll_until(
        _describe_after_delete,
        lambda v: v[0] != "STILL_PRESENT",
        timeout_s=60,
        interval_s=3,
    )
    assert final == ("BackupNotFoundException", not_found_msg), (
        f"expected DescribeBackup after delete to give BackupNotFoundException {not_found_msg!r}, got {final!r}"
    )

    listed_after_delete = ddb.list_backups(TableName=table_name)["BackupSummaries"]
    assert not any(b["BackupArn"] == backup_arn for b in listed_after_delete), listed_after_delete

    redelete_code, redelete_msg = _error(lambda: ddb.delete_backup(BackupArn=backup_arn))
    assert redelete_code == "BackupNotFoundException", (
        f"expected a second DeleteBackup on the now-deleted backup to also 404, got {redelete_code}"
    )
    assert redelete_msg == not_found_msg, f"expected {not_found_msg!r}, got {redelete_msg!r}"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (Code, Message) of a call real AWS refuses. RAISES on unexpected success."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _create_backup_with_retry(ddb, table_name: str, backup_name: str, *, timeout_s: float = 120, interval_s: float = 5) -> dict:
    # Immediately after a table becomes ACTIVE, its continuous-backups
    # infrastructure can still be settling ("Backups are being enabled for
    # ..."), which makes CreateBackup transiently reject with
    # ContinuousBackupsUnavailableException. Retry within a bound instead of
    # treating this as a hard failure.
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return ddb.create_backup(TableName=table_name, BackupName=backup_name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ContinuousBackupsUnavailableException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"CreateBackup still unavailable after {timeout_s}s: {last_err}")


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
        interval_s=3,
    )


def _delete_table_ignore(ddb, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _delete_backup_ignore(ddb, backup_arn: str) -> None:
    try:
        ddb.delete_backup(BackupArn=backup_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "BackupNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
