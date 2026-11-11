"""server-side-point-in-time-recovery-enforced-after-enable."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "server-side-point-in-time-recovery-enforced-after-enable"
GROUP = "server-side"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PITR is DISABLED by default; once enabled, DescribeContinuousBackups shows a recovery window
    (Earliest <= LatestRestorableDateTime). After DeleteTable, Describe and UpdateContinuousBackups
    both report the table not found."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-pitr-")

    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def _cleanup() -> None:
        try:
            ddb.delete_table(TableName=table_name)
        except ddb.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_cleanup)
    _wait_table_active(ddb, table_name)

    def _continuous_backups_desc() -> dict[str, Any]:
        return ddb.describe_continuous_backups(TableName=table_name)["ContinuousBackupsDescription"]

    # Continuous backups are enabled at creation but can take a moment to report ENABLED.
    baseline = _poll_until(
        _continuous_backups_desc,
        lambda d: d.get("ContinuousBackupsStatus") == "ENABLED",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert baseline["ContinuousBackupsStatus"] == "ENABLED", (
        f"expected ContinuousBackupsStatus=ENABLED right after CreateTable, "
        f"got {baseline['ContinuousBackupsStatus']!r}"
    )
    baseline_pitr = baseline.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus")
    assert baseline_pitr == "DISABLED", (
        f"expected PointInTimeRecoveryStatus=DISABLED by default on a new table, got {baseline_pitr!r}"
    )

    ddb.update_continuous_backups(
        TableName=table_name,
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
    )

    def _pitr_desc() -> dict[str, Any]:
        return ddb.describe_continuous_backups(TableName=table_name)["ContinuousBackupsDescription"][
            "PointInTimeRecoveryDescription"
        ]

    final = _poll_until(
        _pitr_desc,
        lambda d: d.get("PointInTimeRecoveryStatus") == "ENABLED",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert final["PointInTimeRecoveryStatus"] == "ENABLED", (
        f"expected PointInTimeRecoveryStatus=ENABLED after UpdateContinuousBackups, "
        f"got {final['PointInTimeRecoveryStatus']!r}"
    )
    earliest = final.get("EarliestRestorableDateTime")
    latest = final.get("LatestRestorableDateTime")
    assert earliest is not None, "expected EarliestRestorableDateTime to be populated once PITR is enabled, got None"
    assert latest is not None, "expected LatestRestorableDateTime to be populated once PITR is enabled, got None"
    assert earliest <= latest, (
        f"expected EarliestRestorableDateTime <= LatestRestorableDateTime, got {earliest!r} > {latest!r}"
    )

    ddb.delete_table(TableName=table_name)

    def _describe_after_delete() -> str | None:
        try:
            ddb.describe_table(TableName=table_name)
            return None
        except ddb.exceptions.ResourceNotFoundException:
            return "ResourceNotFoundException"

    gone = _poll_until(
        _describe_after_delete,
        lambda code: code == "ResourceNotFoundException",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert gone == "ResourceNotFoundException", (
        f"expected DescribeTable to report ResourceNotFoundException after DeleteTable, got {gone!r}"
    )

    try:
        ddb.update_continuous_backups(
            TableName=table_name,
            PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": False},
        )
    except ddb.exceptions.TableNotFoundException as exc:
        message = exc.response["Error"].get("Message")
        assert message == f"Table not found: {table_name}", message
    else:
        raise AssertionError(
            "expected UpdateContinuousBackups against a deleted table to raise TableNotFoundException"
        )


def _wait_table_active(client, table_name: str, timeout_s: float = 120.0, interval_s: float = 2.0) -> None:
    def _status() -> str:
        return client.describe_table(TableName=table_name)["Table"]["TableStatus"]

    _poll_until(_status, lambda s: s == "ACTIVE", timeout_s=timeout_s, interval_s=interval_s)


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
