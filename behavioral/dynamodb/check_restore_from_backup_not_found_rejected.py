"""restore-from-backup-not-found-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-from-backup-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreTableFromBackup naming a nonexistent backup returns BackupNotFoundException and leaves
    no table at the destination, while the identical call against a real backup succeeds, so the
    refusal is about the missing backup."""
    ddb = ctx.client("dynamodb")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # --- positive control: RestoreTableFromBackup against a real backup is accepted ---
    source_table = ctx.unique_name("sim2real-rfb-src-")
    ddb.create_table(
        TableName=source_table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": "restore-from-backup-not-found-rejected"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, source_table))
    _poll_until(
        lambda: ddb.describe_table(TableName=source_table)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )

    backup_name = ctx.unique_name("sim2real-rfb-bk-")

    def _attempt_create_backup() -> dict[str, Any] | None:
        try:
            return ddb.create_backup(TableName=source_table, BackupName=backup_name)
        except ClientError as err:
            # A just-created table has continuous backups enabling in the background; a
            # CreateBackup issued too soon is rejected until that settles.
            if err.response["Error"]["Code"] == "ContinuousBackupsUnavailableException":
                return None
            raise

    backup_arn = _poll_until(
        _attempt_create_backup, lambda resp: resp is not None, timeout_s=60, interval_s=3
    )["BackupDetails"]["BackupArn"]
    ctx.on_cleanup(lambda: _safe_delete_backup(ddb, backup_arn))
    _poll_until(
        lambda: ddb.describe_backup(BackupArn=backup_arn)["BackupDescription"]["BackupDetails"][
            "BackupStatus"
        ],
        lambda status: status == "AVAILABLE",
        timeout_s=90,
        interval_s=3,
    )

    positive_target = ctx.unique_name("sim2real-rfb-pos-")
    positive_resp = ddb.restore_table_from_backup(
        TargetTableName=positive_target, BackupArn=backup_arn
    )
    assert positive_resp["TableDescription"]["TableName"] == positive_target, (
        "positive control: expected RestoreTableFromBackup to accept a real backup, got "
        f"table name {positive_resp['TableDescription']['TableName']!r}"
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, positive_target))

    # --- negative: RestoreTableFromBackup referencing a nonexistent backup id ---
    # Real DynamoDB backup ids are a 14-digit (zero-padded) millisecond epoch timestamp,
    # a dash, and an 8-character hex suffix (e.g. "01639426382000-1509b1b3"). A backup id
    # of the wrong shape (e.g. only 12 digits) is rejected by ARN-shape validation with a
    # generic ValidationException *before* DynamoDB ever looks up whether a backup with
    # that id exists — so it never reaches BackupNotFoundException. Use a well-formed but
    # nonexistent id so the request actually exercises the not-found lookup.
    fake_table = ctx.unique_name("sim2real-notable-")
    fake_backup_id = f"0{int(time.time() * 1000)}-abcdef03"
    fake_arn = (
        f"arn:aws:dynamodb:{ctx.region}:{account_id}:table/{fake_table}/backup/{fake_backup_id}"
    )
    target_name = ctx.unique_name("sim2real-restored-")
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, target_name))

    def _restore():
        ddb.restore_table_from_backup(TargetTableName=target_name, BackupArn=fake_arn)

    code, message = _error(_restore)
    assert code == "BackupNotFoundException", f"expected BackupNotFoundException, got {code}"
    expected = f"Backup not found: {fake_arn}"
    assert message == expected, f"unexpected message {message!r}"

    # the rejected restore must not have created a table at the destination — independent read
    not_found_code, not_found_message = _error(lambda: ddb.describe_table(TableName=target_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"restore of {target_name!r} was rejected but the table is still describable "
        f"(code={not_found_code!r}) — a table was created despite the rejection"
    )
    expected_not_found = f"Requested resource not found: Table: {target_name} not found"
    assert not_found_message == expected_not_found, f"unexpected message {not_found_message!r}"


# ===== helpers =====
def _error(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


def _safe_delete_table(ddb, table_name, *, timeout_s: float = 300.0):
    """Teardown delete: a table already gone is fine; ResourceInUseException (a restore still
    creating the table) is retried every 2 s up to timeout_s; any other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe_delete_backup(ddb, backup_arn):
    try:
        ddb.delete_backup(BackupArn=backup_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "BackupNotFoundException":
            raise


def _delete_table_if_exists(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
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

