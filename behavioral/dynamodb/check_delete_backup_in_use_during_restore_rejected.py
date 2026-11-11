"""delete-backup-in-use-during-restore-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-backup-in-use-during-restore-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


def _remaining_budget(start: float, total: float = 850.0, floor: float = 30.0) -> float:
    # Leave a margin under the 900s per-check ceiling for the steps after the restore wait.
    return max(floor, total - (time.monotonic() - start))


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBackup on a backup that is actively being restored from (RestoreTableFromBackup
    still in progress) raises BackupInUseException; once the restore completes, deleting the
    same backup succeeds (positive control) and the backup transitions to DELETED."""
    start = time.monotonic()
    ddb = ctx.client("dynamodb")

    source_name = ctx.unique_name("sim2real-behav-src-")
    # PROVISIONED with a small fixed capacity (rather than PAY_PER_REQUEST) for both the
    # source and the restored table: on real AWS an on-demand table's restore needs
    # on-demand capacity metadata allocated on top of the storage-partition provisioning
    # every restore does, which measurably lengthens the CREATING->ACTIVE window versus a
    # small fixed-capacity PROVISIONED table.
    ddb.create_table(
        TableName=source_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=source_name))
    _wait_table_status(ctx, source_name, "ACTIVE")
    _wait_continuous_backups_ready(ctx, source_name)
    ddb.put_item(TableName=source_name, Item={"pk": {"S": "seed-item"}})

    backup_arn = ddb.create_backup(
        TableName=source_name, BackupName=ctx.unique_name("sim2real-behav-bkp-")
    )["BackupDetails"]["BackupArn"]
    # DynamoDB's TagResource rejects a backup ARN outright ("Provided Arn is not a DynamoDB
    # resource arn") -- backups are not taggable; only the source and restored tables are.
    ctx.on_cleanup(lambda: _safe_delete_backup(ctx, backup_arn))
    _wait_backup_status(ctx, backup_arn, "AVAILABLE")

    target_name = ctx.unique_name("sim2real-behav-restored-")
    restore_desc = ddb.restore_table_from_backup(
        TargetTableName=target_name,
        BackupArn=backup_arn,
        BillingModeOverride="PROVISIONED",
        ProvisionedThroughputOverride={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
    )["TableDescription"]
    ctx.on_cleanup(lambda: _cleanup_delete_table(ctx, target_name))
    assert restore_desc["TableStatus"] == "CREATING", (
        f'expected the just-initiated restore target to be CREATING, got {restore_desc["TableStatus"]}'
    )
    assert restore_desc["RestoreSummary"]["RestoreInProgress"] is True, (
        f'expected RestoreSummary.RestoreInProgress True on a fresh restore, '
        f'got {restore_desc["RestoreSummary"]["RestoreInProgress"]}'
    )

    # Delete immediately, while the restore is (very likely) still in progress.
    code, message = _error_detail(lambda: ddb.delete_backup(BackupArn=backup_arn))
    assert code == "BackupInUseException", f"expected BackupInUseException, got {code}"
    in_use_message = f"Backup is being used to restore table: {backup_arn}"
    assert message == in_use_message, f"expected message {in_use_message!r}, got {message!r}"

    # The backup must still exist and be usable, unaffected by the rejected delete.
    still_there = ddb.describe_backup(BackupArn=backup_arn)["BackupDescription"]
    assert still_there["BackupDetails"]["BackupStatus"] == "AVAILABLE", (
        f'expected the backup to remain AVAILABLE after its rejected delete, '
        f'got {still_there["BackupDetails"]["BackupStatus"]}'
    )

    # Positive control: once the restore finishes, the backup is no longer "in use" and
    # DeleteBackup succeeds. A restore can take longer than 600s even for a small PROVISIONED
    # table, so the wait uses nearly all of the per-check budget.
    active_desc = _wait_table_status(
        ctx, target_name, "ACTIVE", timeout_s=_remaining_budget(start), interval_s=5
    )
    # Only tag once the table is ACTIVE: right after RestoreTableFromBackup, TagResource on
    # its TableArn fails with ResourceNotFoundException.
    ddb.tag_resource(
        ResourceArn=active_desc["TableArn"], Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}]
    )
    delete_resp = ddb.delete_backup(BackupArn=backup_arn)["BackupDescription"]
    assert delete_resp["BackupDetails"]["BackupStatus"] == "DELETED", (
        f'expected the once-restore-completes delete to report DELETED, '
        f'got {delete_resp["BackupDetails"]["BackupStatus"]}'
    )

    # Read back through a different operation: the backup must actually be gone.
    gone_code = _poll_until_not_found(ctx, backup_arn)
    assert gone_code == "BackupNotFoundException", (
        f"expected an independent DescribeBackup to 404 after the backup was deleted, got {gone_code}"
    )


def _cleanup_delete_table(ctx, table_name, timeout_s=45, interval_s=3):
    # A still-CREATING or just-restored table can refuse DeleteTable with ResourceInUseException
    # for a while; retry within the 60s cleanup budget rather than leaking on the first refusal.
    ddb = ctx.client("dynamodb")
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
            time.sleep(interval_s)


def _safe_delete_backup(ctx, backup_arn):
    ddb = ctx.client("dynamodb")
    try:
        ddb.delete_backup(BackupArn=backup_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("BackupNotFoundException", "BackupInUseException"):
            raise


def _error_detail(fn):
    """The (code, message) a rejected call returned; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, the call succeeded: {result!r}")


def _wait_table_status(ctx, table_name, target_status, timeout_s=180, interval_s=3):
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


def _wait_backup_status(ctx, backup_arn, target_status, timeout_s=180, interval_s=3):
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = ddb.describe_backup(BackupArn=backup_arn)["BackupDescription"]
        last = desc["BackupDetails"]["BackupStatus"]
        if last == target_status:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"backup {backup_arn} never reached {target_status}, last={last}")


def _poll_until_not_found(ctx, backup_arn, timeout_s=60, interval_s=2):
    # Real AWS does not always retire a just-deleted backup's DescribeBackup instantly; it may
    # answer DELETED for a short window before 404ing. Poll for the terminal not-found code
    # rather than trusting the first read.
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ddb.describe_backup(BackupArn=backup_arn)["BackupDescription"]["BackupDetails"][
                "BackupStatus"
            ]
        except ClientError as err:
            last = err.response["Error"]["Code"]
            if last == "BackupNotFoundException":
                return last
        time.sleep(interval_s)
    return last  # deliberately not raised: the caller's own assert is the check on this value


def _wait_continuous_backups_ready(ctx, table_name, timeout_s=180, interval_s=3):
    # Immediately after a table reaches ACTIVE, DynamoDB is still provisioning the
    # continuous-backups infrastructure that CreateBackup depends on; calling CreateBackup
    # too early raises ContinuousBackupsUnavailableException ("Backups are being enabled
    # for this table"). Poll until the infra itself is ready before issuing any backup call.
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
