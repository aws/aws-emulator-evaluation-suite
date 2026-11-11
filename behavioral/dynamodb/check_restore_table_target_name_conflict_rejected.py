"""restore-table-target-name-conflict-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-table-target-name-conflict-rejected"
GROUP = "state-machine"
SERVICES = ["dynamodb"]

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav-restconf"},
]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreTableFromBackup to the name of a live table raises TableAlreadyExistsException with the exact message and
    leaves that table and its data unchanged; once the table is deleted, the same call is accepted and restores
    from that backup.
    """
    ddb = ctx.client("dynamodb")

    source_name = ctx.unique_name("sim2real-behav-restconf-src-")
    ddb.create_table(
        TableName=source_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_TAGS_KV,
    )
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, source_name))
    _wait_table_active(ddb, source_name)
    ddb.put_item(TableName=source_name, Item={"pk": {"S": "k"}, "v": {"S": "src-data"}})

    backup_name = ctx.unique_name("sim2real-behav-restconf-bkp-")

    def _attempt_create_backup() -> dict[str, Any] | None:
        try:
            return ddb.create_backup(TableName=source_name, BackupName=backup_name)
        except ClientError as err:
            # A just-created table has continuous backups enabling in the background; a
            # CreateBackup issued too soon is rejected until that settles.
            if err.response["Error"]["Code"] == "ContinuousBackupsUnavailableException":
                return None
            raise

    backup_arn = _poll_until(
        _attempt_create_backup, lambda resp: resp is not None, timeout_s=60, interval_s=3
    )["BackupDetails"]["BackupArn"]
    ctx.on_cleanup(lambda: _delete_backup_ignore(ddb, backup_arn))
    _poll_until(
        lambda: ddb.describe_backup(BackupArn=backup_arn)["BackupDescription"]["BackupDetails"]["BackupStatus"],
        lambda s: s == "AVAILABLE",
        timeout_s=120,
        interval_s=3,
    )

    colliding_name = ctx.unique_name("sim2real-behav-restconf-collide-")
    ddb.create_table(
        TableName=colliding_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_TAGS_KV,
    )
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, colliding_name))
    _wait_table_active(ddb, colliding_name)
    ddb.put_item(TableName=colliding_name, Item={"pk": {"S": "existing"}, "v": {"S": "must-not-be-overwritten"}})
    before = ddb.describe_table(TableName=colliding_name)["Table"]

    code, message = _expect_rejection(
        lambda: ddb.restore_table_from_backup(TargetTableName=colliding_name, BackupArn=backup_arn)
    )
    assert code == "TableAlreadyExistsException", f"expected TableAlreadyExistsException, got {code!r}"
    expected = f"Table already exists: {colliding_name}"
    assert message == expected, f"unexpected message {message!r}"

    after = ddb.describe_table(TableName=colliding_name)["Table"]
    assert after["TableStatus"] == "ACTIVE", (
        f"a rejected restore left the colliding table as {after['TableStatus']!r}, expected it to "
        "remain ACTIVE"
    )
    assert after["CreationDateTime"] == before["CreationDateTime"], (
        f"the colliding table's CreationDateTime moved from {before['CreationDateTime']!r} to "
        f"{after['CreationDateTime']!r} across a rejected restore, meaning it was replaced"
    )
    assert after["TableArn"] == before["TableArn"], (
        f"the colliding table's ARN changed from {before['TableArn']!r} to {after['TableArn']!r} "
        "across a rejected restore"
    )
    still_there = ddb.get_item(TableName=colliding_name, Key={"pk": {"S": "existing"}}, ConsistentRead=True)
    assert still_there.get("Item", {}).get("v", {}).get("S") == "must-not-be-overwritten", (
        f"the colliding table's pre-existing item did not survive the rejected restore: {still_there!r}"
    )
    # The would-be restore target key ("k") from the source table must never appear.
    absent = ddb.get_item(TableName=colliding_name, Key={"pk": {"S": "k"}}, ConsistentRead=True)
    assert "Item" not in absent, (
        f"the source table's key leaked into the colliding table despite the restore being "
        f"rejected: {absent!r}"
    )

    # Recovery leg: remove the one thing that made the call illegitimate, then repeat the
    # IDENTICAL call (same TargetTableName, same BackupArn). This is what proves the rejection
    # above is attributable to the name collision specifically -- a target that rejects every
    # RestoreTableFromBackup call (or one that hardcodes TableAlreadyExistsException) fails here
    # too, where a bare error-code check on the first call alone could not tell the difference.
    ddb.delete_table(TableName=colliding_name)
    _wait_table_gone(ddb, colliding_name)

    # The restore is asserted at acceptance, not polled to ACTIVE: a restore from backup takes
    # minutes even for a near-empty table.
    restore_resp = _expect_success(
        lambda: ddb.restore_table_from_backup(TargetTableName=colliding_name, BackupArn=backup_arn)
    )
    ctx.on_cleanup(lambda: _delete_table_retrying(ddb, colliding_name))
    assert restore_resp["TableDescription"]["TableName"] == colliding_name, (
        f"the recovered restore call reported TableName "
        f"{restore_resp['TableDescription']['TableName']!r}, expected {colliding_name!r}"
    )
    assert restore_resp["TableDescription"]["RestoreSummary"]["SourceBackupArn"] == backup_arn, (
        f"the recovered restore call's own RestoreSummary names backup "
        f"{restore_resp['TableDescription'].get('RestoreSummary')!r}, expected source {backup_arn!r}"
    )

    # Terminal assertion: an INDEPENDENT read (DescribeTable), never the mutating restore call's
    # own echo, confirming from a second vantage point that the table now exists at the
    # destination and is genuinely tied to our backup -- not merely a coincidentally-accepted
    # CreateTable. Taken immediately rather than after polling to ACTIVE (see docstring).
    independent = ddb.describe_table(TableName=colliding_name)["Table"]
    assert independent["TableName"] == colliding_name, (
        f"the independent read named table {independent['TableName']!r}, expected {colliding_name!r}"
    )
    assert independent["RestoreSummary"]["SourceBackupArn"] == backup_arn, (
        f"the independent read's RestoreSummary names backup "
        f"{independent.get('RestoreSummary')!r}, expected source {backup_arn!r}"
    )


def _expect_rejection(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _expect_success(fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except ClientError as err:
        raise AssertionError(
            f"expected this call to succeed now that the conflict is removed, but it was rejected "
            f"with {err.response['Error']['Code']!r}: {err.response['Error'].get('Message')!r}"
        ) from err


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


def _wait_table_gone(ddb, table_name: str, timeout_s: float = 60) -> None:
    def _probe() -> bool:
        try:
            ddb.describe_table(TableName=table_name)
            return False
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
            raise

    _poll_until(_probe, lambda gone: gone, timeout_s=timeout_s, interval_s=2)


def _delete_table_ignore(ddb, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _delete_table_retrying(ddb, table_name: str, attempts: int = 5, interval_s: float = 5.0) -> None:
    """A table just restored from backup is left in CREATING and DynamoDB refuses DeleteTable
    until it settles -- which routinely outlasts the whole cleanup budget. Retry within a modest
    slice of it, then log and give up rather than starving every other cleanup in this check."""
    for attempt in range(attempts):
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or attempt == attempts - 1:
                raise RuntimeError(
                    f"table {table_name!r} not deleted during cleanup: {code}"
                ) from err
            time.sleep(interval_s)


def _delete_backup_ignore(ddb, backup_arn: str) -> None:
    try:
        ddb.delete_backup(BackupArn=backup_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "BackupNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
