"""delete-backup-not-found-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-backup-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBackup on an existing backup succeeds with status DELETED; the same call on that deleted backup,
    repeated, and on a backup id that never existed raises BackupNotFoundException with the exact message.
    """
    ddb = ctx.client("dynamodb")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    table_name = ctx.unique_name("sim2real-behav-notfound-tbl-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _wait_table_active(ddb, table_name)
    _wait_continuous_backups_enabled(ddb, table_name)

    backup_name = ctx.unique_name("sim2real-behav-notfound-bk-")
    backup_arn = _create_backup_with_retry(ddb, table_name, backup_name)
    ctx.on_cleanup(lambda: _safe_delete_backup(ddb, backup_arn))
    _wait_backup_available(ddb, backup_arn)

    # Positive control: DeleteBackup on a real, existing backup succeeds. Without
    # this, a target that returns BackupNotFoundException for every DeleteBackup
    # call — never actually deleting anything — would pass the negative below too.
    delete_resp = ddb.delete_backup(BackupArn=backup_arn)
    deleted_status = delete_resp["BackupDescription"]["BackupDetails"]["BackupStatus"]
    assert deleted_status == "DELETED", f"expected DELETED, got {deleted_status}"

    # Independent read confirms the backup is actually gone.
    gone_code, gone_msg = _error(lambda: ddb.describe_backup(BackupArn=backup_arn))
    assert gone_code == "BackupNotFoundException", f"expected BackupNotFoundException, got {gone_code}"
    expected_gone = f"Backup not found: {backup_arn}"
    assert gone_msg == expected_gone, f"expected message {expected_gone!r}, got {gone_msg!r}"

    # A second DeleteBackup against that now-dead id is rejected too — the delete
    # did not silently no-op or succeed twice.
    redelete_code, redelete_msg = _error(lambda: ddb.delete_backup(BackupArn=backup_arn))
    assert redelete_code == "BackupNotFoundException", (
        f"expected BackupNotFoundException, got {redelete_code}"
    )
    assert redelete_msg == expected_gone, (
        f"expected message {expected_gone!r}, got {redelete_msg!r}"
    )

    # A backup id that never existed at all is rejected the same way. Real
    # DynamoDB backup ids are a 14-digit (zero-padded) millisecond epoch timestamp,
    # a dash, and an 8-character hex suffix (e.g. "01639426382000-1509b1b3"). A
    # backup id of the wrong shape (e.g. only 12 digits) is rejected by ARN-shape
    # validation with a generic ValidationException *before* DynamoDB ever looks
    # up whether a backup with that id exists — so it never reaches
    # BackupNotFoundException. Use a well-formed but nonexistent id so the
    # request actually exercises the not-found lookup.
    fake_backup_id = f"0{int(time.time() * 1000)}-abcdef02"
    fake_arn = (
        f"arn:aws:dynamodb:{ctx.region}:{account_id}:table/{table_name}/backup/{fake_backup_id}"
    )
    never_existed_code, never_existed_msg = _error(lambda: ddb.delete_backup(BackupArn=fake_arn))
    assert never_existed_code == "BackupNotFoundException", (
        f"expected BackupNotFoundException, got {never_existed_code}"
    )
    expected_fake = f"Backup not found: {fake_arn}"
    assert never_existed_msg == expected_fake, (
        f"expected message {expected_fake!r}, got {never_existed_msg!r}"
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
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _wait_continuous_backups_enabled(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_continuous_backups(TableName=table_name)[
            "ContinuousBackupsDescription"
        ]
        if desc["ContinuousBackupsStatus"] == "ENABLED":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"continuous backups for {table_name} never became ENABLED")


def _create_backup_with_retry(ddb, table_name, backup_name, timeout_s=120.0, interval_s=5.0):
    # Immediately after a table becomes ACTIVE, its continuous-backups
    # infrastructure can still be settling ("Backups are being enabled for
    # ..."), which makes CreateBackup transiently reject with
    # ContinuousBackupsUnavailableException. Retry within a bound instead of
    # treating this as a hard failure.
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ddb.create_backup(TableName=table_name, BackupName=backup_name)[
                "BackupDetails"
            ]["BackupArn"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ContinuousBackupsUnavailableException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"CreateBackup still unavailable after {timeout_s}s: {last_err}")


def _wait_backup_available(ddb, backup_arn, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_backup(BackupArn=backup_arn)["BackupDescription"]
        if desc["BackupDetails"]["BackupStatus"] == "AVAILABLE":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"backup {backup_arn} never became AVAILABLE")


def _safe_delete_table(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_backup(ddb, backup_arn):
    try:
        ddb.delete_backup(BackupArn=backup_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "BackupNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
