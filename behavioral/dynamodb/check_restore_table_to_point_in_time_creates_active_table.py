"""restore-table-to-point-in-time-creates-active-table."""

from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "restore-table-to-point-in-time-creates-active-table"
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
    """RestoreTableToPointInTime produces a new table that transitions to ACTIVE and carries
    over the data present on the source table at restore time."""
    # The harness enforces ONE hard wall-clock budget for the WHOLE check regardless of
    # any individual poll's own timeout_s — a poll timeout bigger than what's left of that budget
    # can never actually be honored; it only guarantees the process gets killed mid-poll with an
    # unhelpful "Check timed out" instead of a clean assertion. Track elapsed time from the start
    # and hand the dominant, unavoidably-async stage (the restore reaching ACTIVE) whatever of the
    # real budget remains, instead of a static value that outruns the cap.
    # `total` is the check's wall-clock budget less a 100 s margin for the steps after the
    # wait.
    start = time.monotonic()

    def _remaining_budget(total: float = 1700.0, floor: float = 30.0) -> float:
        return max(floor, total - (time.monotonic() - start))

    ddb = ctx.client("dynamodb")
    source_table = ctx.unique_name("sim2real-behav-rpitr-src-")
    key_schema = [{"AttributeName": "pk", "KeyType": "HASH"}]
    ddb.create_table(
        TableName=source_table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=key_schema,
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, source_table))
    _poll_until(
        lambda: ddb.describe_table(TableName=source_table)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )

    ddb.put_item(
        TableName=source_table, Item={"pk": {"S": "seed-item"}, "val": {"S": "world"}}
    )

    target_table = ctx.unique_name("sim2real-behav-rpitr-dst-")

    # The harness enforces one hard wall-clock budget for the WHOLE check regardless of any
    # individual poll's own timeout_s, and RestoreTableToPointInTime's own completion is the
    # dominant cost against that budget. Enable PITR as the FIRST action once the source table is
    # ACTIVE (rather than folding it into the restore-attempt retry loop below) so its "latest
    # restorable time" gets the maximum head start to become usable while the item write above
    # runs, instead of only starting to settle deep into the check's wall-clock budget.
    _enable_pitr_with_retry(ddb, source_table)

    def _attempt_restore() -> dict[str, Any] | None:
        try:
            return ddb.restore_table_to_point_in_time(
                SourceTableName=source_table,
                TargetTableName=target_table,
                UseLatestRestorableTime=True,
            )
        except Exception as exc:  # noqa: BLE001
            code = _error_code_from_exc(exc)
            if code in (
                "InvalidRestoreTimeException",
                "PointInTimeRecoveryUnavailableException",
            ):
                return None
            raise

    restore_resp = _poll_until(
        _attempt_restore,
        lambda resp: resp is not None,
        timeout_s=90,
        interval_s=2,
    )
    assert restore_resp["TableDescription"]["TableName"] == target_table
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, target_table))

    # Restoring a table to a point in time (even a tiny table) commonly takes DynamoDB a couple
    # of minutes to reach ACTIVE on real AWS — give this dominant, unavoidably-async stage
    # whatever is left of the check's wall-clock budget (a static timeout_s bigger than that
    # remaining budget can never be honored, so the poll uses the real remaining time rather than
    # a number that outruns it). RestoreSummary is carried by RestoreTableToPointInTime's own TableDescription;
    # DescribeTable on the ACTIVE table was observed on real AWS to omit it.
    assert "RestoreSummary" in restore_resp["TableDescription"]
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
        "restored table is missing the item written before restore"
    )
    assert restored_item["val"]["S"] == "world"


def _enable_pitr_with_retry(
    ddb: Any, table_name: str, *, timeout_s: float = 60, interval_s: float = 2
) -> None:
    """A just-created table has continuous backups enabling in the background; an
    UpdateContinuousBackups issued too soon is rejected until that settles — retry for a
    bounded time rather than treating that as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_continuous_backups(
                TableName=table_name,
                PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
            )
            return
        except Exception as exc:  # noqa: BLE001
            if _error_code_from_exc(
                exc
            ) == "ContinuousBackupsUnavailableException" and (
                time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


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
