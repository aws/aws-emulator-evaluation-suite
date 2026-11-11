"""restore-table-from-backup-creates-active-table."""

from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "restore-table-from-backup-creates-active-table"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """RestoreTableFromBackup produces a new table that reaches ACTIVE with the source
    backup's schema, and the data present at backup time is present in the restored table."""
    # The runner enforces ONE hard wall-clock budget for the WHOLE check regardless of any
    # individual poll's own timeout_s — a poll timeout bigger than what's left of that budget
    # can never actually be honored; it only guarantees the process gets killed mid-poll with an
    # unhelpful "Check timed out" instead of a clean assertion. Track elapsed time from the start
    # and hand the dominant, unavoidably-async stage (the restore reaching ACTIVE) whatever of the
    # real budget remains, instead of a static value that outruns the cap.
    # `total` is the check's wall-clock budget less a 100 s margin for the steps after the
    # restore-active wait.
    start = time.monotonic()

    def _remaining_budget(total: float = 1700.0, floor: float = 30.0) -> float:
        return max(floor, total - (time.monotonic() - start))

    ddb = ctx.client("dynamodb")
    source_table = ctx.unique_name("sim2real-behav-rfb-src-")
    key_schema = [{"AttributeName": "pk", "KeyType": "HASH"}]
    attr_defs = [{"AttributeName": "pk", "AttributeType": "S"}]
    ddb.create_table(
        TableName=source_table,
        AttributeDefinitions=attr_defs,
        KeySchema=key_schema,
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, source_table))
    _poll_until(
        lambda: ddb.describe_table(TableName=source_table)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )
    ddb.put_item(
        TableName=source_table, Item={"pk": {"S": "seed-item"}, "val": {"S": "hello"}}
    )

    backup_name = ctx.unique_name("sim2real-behav-rfb-bk-")

    def _attempt_create_backup() -> dict[str, Any] | None:
        try:
            return ddb.create_backup(TableName=source_table, BackupName=backup_name)
        except Exception as exc:  # noqa: BLE001
            # A just-created table has continuous backups enabling in the background; a
            # CreateBackup issued too soon is rejected until that settles.
            if _error_code_from_exc(exc) == "ContinuousBackupsUnavailableException":
                return None
            raise

    # The harness enforces one hard wall-clock budget for the WHOLE check regardless of any
    # individual poll's own timeout_s, and RestoreTableFromBackup's own completion is the
    # dominant cost against that budget — keep every OTHER stage as tight as real AWS allows
    # so the terminal wait gets the maximum remaining share.
    backup_arn = _poll_until(
        _attempt_create_backup,
        lambda resp: resp is not None,
        timeout_s=60,
        interval_s=3,
    )["BackupDetails"]["BackupArn"]
    ctx.on_cleanup(lambda: _safe_delete_backup(ddb, backup_arn))
    _poll_until(
        lambda: ddb.describe_backup(BackupArn=backup_arn)["BackupDescription"][
            "BackupDetails"
        ]["BackupStatus"],
        lambda status: status == "AVAILABLE",
        timeout_s=90,
        interval_s=3,
    )

    target_table = ctx.unique_name("sim2real-behav-rfb-dst-")
    restore_resp = ddb.restore_table_from_backup(
        TargetTableName=target_table, BackupArn=backup_arn
    )
    assert restore_resp["TableDescription"]["TableName"] == target_table
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, target_table))

    # Restoring a table from a backup (even a tiny one) commonly takes DynamoDB a couple of
    # minutes to reach ACTIVE on real AWS — give this dominant, unavoidably-async stage whatever
    # is left of the runner's hard wall-clock budget (a static timeout_s bigger than that
    # remaining budget can never be honored: the runner kills the whole check at the ceiling
    # regardless, so the poll should use the real remaining time rather than a number that
    # outruns it).
    # RestoreSummary is carried by RestoreTableFromBackup's own TableDescription; DescribeTable on
    # the ACTIVE table was observed on real AWS to omit it, for the whole 1700s poll.
    assert restore_resp["TableDescription"]["RestoreSummary"]["SourceBackupArn"] == backup_arn
    described = _poll_until(
        lambda: ddb.describe_table(TableName=target_table)["Table"],
        lambda table: table["TableStatus"] == "ACTIVE",
        timeout_s=_remaining_budget(),
        interval_s=5,
    )
    assert described["TableStatus"] == "ACTIVE"
    assert described["KeySchema"] == key_schema

    restored_item = ddb.get_item(
        TableName=target_table, Key={"pk": {"S": "seed-item"}}
    ).get("Item")
    assert restored_item is not None, (
        "restored table is missing the item present at backup time"
    )
    assert restored_item["val"]["S"] == "hello"


def _safe_delete_table(ddb: Any, table_name: str, timeout_s: float = 240.0) -> None:
    """Delete the table; an absent table is done. A table still CREATING or UPDATING refuses the
    delete with ResourceInUseException, which is retried until *timeout_s*."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ddb.exceptions.ResourceNotFoundException:
            return
        except ddb.exceptions.ResourceInUseException:
            if time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _safe_delete_backup(ddb: Any, backup_arn: str) -> None:
    """Delete the backup; one already gone is done."""
    try:
        ddb.delete_backup(BackupArn=backup_arn)
    except ddb.exceptions.BackupNotFoundException:
        pass


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


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
