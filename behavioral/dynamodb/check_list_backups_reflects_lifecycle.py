"""list-backups-reflects-lifecycle."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-backups-reflects-lifecycle"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListBackups includes a backup only between its CreateBackup and DeleteBackup calls;
    after DeleteBackup, an independent DescribeBackup and a second DeleteBackup both 404
    (BackupNotFoundException)."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-lbk-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": "list-backups-reflects-lifecycle"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )

    backup_name = ctx.unique_name("sim2real-behav-lbkname-")
    names_before = _list_backup_names(ddb, table_name)
    assert backup_name not in names_before, (
        f"unique backup name {backup_name!r} already present before creation: {names_before!r}"
    )

    backup_arn = _create_backup_with_retry(ddb, table_name, backup_name)["BackupDetails"][
        "BackupArn"
    ]
    ctx.on_cleanup(lambda: _safe_delete_backup(ddb, backup_arn))
    _poll_until(
        lambda: ddb.describe_backup(BackupArn=backup_arn)["BackupDescription"]["BackupDetails"][
            "BackupStatus"
        ],
        lambda status: status == "AVAILABLE",
        timeout_s=180,
        interval_s=3,
    )

    names_present = _poll_until(
        lambda: _list_backup_names(ddb, table_name),
        lambda names: backup_name in names,
        timeout_s=60,
        interval_s=3,
    )
    assert backup_name in names_present, (
        f"expected {backup_name!r} in ListBackups while the backup is AVAILABLE, "
        f"got {names_present!r}"
    )

    ddb.delete_backup(BackupArn=backup_arn)

    names_absent = _poll_until(
        lambda: _list_backup_names(ddb, table_name),
        lambda names: backup_name not in names,
        timeout_s=120,
        interval_s=3,
    )
    assert backup_name not in names_absent, (
        f"expected {backup_name!r} absent from ListBackups after DeleteBackup, "
        f"got {names_absent!r}"
    )

    expected_message = f"Backup not found: {backup_arn}"
    deadline = time.monotonic() + 60
    while True:
        try:
            described = ddb.describe_backup(BackupArn=backup_arn)
        except ClientError as exc:
            final_err = exc.response.get("Error", {})
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"DescribeBackup still answers for the deleted backup after 60s: {described!r}"
            )
        time.sleep(3)
    assert final_err.get("Code") == "BackupNotFoundException", (
        f"expected DescribeBackup on the deleted backup to 404 with "
        f"BackupNotFoundException, got {final_err.get('Code')!r}"
    )
    assert final_err.get("Message") == expected_message, (
        f"expected DescribeBackup message {expected_message!r}, got {final_err.get('Message')!r}"
    )

    redelete_err = _error(lambda: ddb.delete_backup(BackupArn=backup_arn))
    assert redelete_err.get("Code") == "BackupNotFoundException", (
        f"expected a second DeleteBackup on the already-deleted backup to 404 with "
        f"BackupNotFoundException, got {redelete_err.get('Code')!r}"
    )
    assert redelete_err.get("Message") == expected_message, (
        f"expected DeleteBackup message {expected_message!r}, got {redelete_err.get('Message')!r}"
    )


def _list_backup_names(ddb: Any, table_name: str) -> list[str]:
    resp = ddb.list_backups(TableName=table_name)
    return [s["BackupName"] for s in resp.get("BackupSummaries", [])]


def _create_backup_with_retry(
    ddb: Any, table_name: str, backup_name: str, *, timeout_s: float = 180, interval_s: float = 5
) -> dict:
    # Immediately after a table becomes ACTIVE, its continuous-backups infrastructure can
    # still be settling, which makes CreateBackup transiently reject with
    # ContinuousBackupsUnavailableException. Retry within a bound instead of treating this
    # as a hard failure.
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


def _error(fn: Callable[[], Any]) -> dict:
    """The Error dict of a call that MUST be refused; RAISES if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _safe_delete_table(ddb: Any, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


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
