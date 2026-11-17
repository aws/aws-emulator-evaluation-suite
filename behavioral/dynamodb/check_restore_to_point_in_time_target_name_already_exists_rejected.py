"""restore-to-point-in-time-target-name-already-exists-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-to-point-in-time-target-name-already-exists-rejected"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreTableToPointInTime onto a TargetTableName held by a live table is refused
    TableAlreadyExistsException and leaves that table untouched; once the occupying table is
    removed, the identical restore succeeds.
    """
    ddb = ctx.client("dynamodb")

    source_table = ctx.unique_name("sim2real-behav-rtpit-src-")
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
    _poll_until(
        lambda: ddb.describe_continuous_backups(TableName=source_table)[
            "ContinuousBackupsDescription"
        ]["ContinuousBackupsStatus"],
        lambda status: status == "ENABLED",
        timeout_s=120,
        interval_s=3,
    )
    ddb.update_continuous_backups(
        TableName=source_table,
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
    )
    _poll_until(
        lambda: ddb.describe_continuous_backups(TableName=source_table)[
            "ContinuousBackupsDescription"
        ]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"],
        lambda status: status == "ENABLED",
        timeout_s=120,
        interval_s=3,
    )

    # A second, already-existing, live table occupies the name we will (illegitimately) ask
    # RestoreTableToPointInTime to target.
    occupied_table = ctx.unique_name("sim2real-behav-rtpit-occupied-")
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

    # Immediately after PITR turns on, a restorable time may take a few seconds to become
    # available (PointInTimeRecoveryUnavailableException) -- ride that out, but the collision
    # we are asserting is TableAlreadyExistsException.
    code, message = _retry_restore_past_unavailable(
        ddb, source_table, occupied_table, timeout_s=60, interval_s=3
    )
    assert code == "TableAlreadyExistsException", (
        f"expected TableAlreadyExistsException, got {code!r}; message was {message!r}"
    )
    expected = f"Table already exists: {occupied_table}"
    assert message == expected, f"unexpected message {message!r}"

    # The occupied table must be completely unaffected by the rejected restore attempt.
    still_active = ddb.describe_table(TableName=occupied_table)["Table"]["TableStatus"]
    assert still_active == "ACTIVE", (
        f"expected the occupied table to remain ACTIVE after the rejected restore, "
        f"got {still_active!r}"
    )

    # Remove the obstruction and demand the identical call now succeeds. A target that rejects
    # RestoreTableToPointInTime unconditionally with this code -- rather than only when the name
    # collides -- passes every assertion above and must fail here.
    ddb.delete_table(TableName=occupied_table)
    _poll_until(
        lambda: _table_status_or_gone(ddb, occupied_table),
        lambda status: status is None,
        timeout_s=120,
        interval_s=3,
    )
    table_desc = _retry_restore_until_accepted(
        ddb, source_table, occupied_table, timeout_s=60, interval_s=3
    )
    assert table_desc["TableStatus"] in ("CREATING", "ACTIVE"), table_desc
    assert table_desc["RestoreSummary"]["SourceTableArn"].endswith(f"table/{source_table}"), (
        table_desc["RestoreSummary"]
    )


# ===== helpers =====

def _retry_restore_past_unavailable(
    ddb: Any, source_table: str, target_table: str, *, timeout_s: float, interval_s: float
) -> tuple[str, str]:
    """Retry RestoreTableToPointInTime past the transient PointInTimeRecoveryUnavailableException
    window; return the (code, message) of the first *other* rejection."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = ddb.restore_table_to_point_in_time(
                SourceTableName=source_table,
                TargetTableName=target_table,
                UseLatestRestorableTime=True,
            )
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "PointInTimeRecoveryUnavailableException" or time.monotonic() >= deadline:
                return err["Code"], err.get("Message")
            time.sleep(interval_s)
            continue
        raise AssertionError(
            f"expected a rejection, but the call succeeded and returned {result!r}"
        )


def _retry_restore_until_accepted(
    ddb: Any, source_table: str, target_table: str, *, timeout_s: float, interval_s: float
) -> dict:
    """DynamoDB may briefly still consider a just-deleted name reserved; retry the restore call
    itself (not just the readiness poll) until it is accepted."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ddb.restore_table_to_point_in_time(
                SourceTableName=source_table,
                TargetTableName=target_table,
                UseLatestRestorableTime=True,
            )["TableDescription"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("TableAlreadyExistsException", "PointInTimeRecoveryUnavailableException"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"the identical restore was still rejected as {code!r} "
                    f"{timeout_s}s after the occupying table was deleted"
                )
            time.sleep(interval_s)


def _table_status_or_gone(ddb: Any, table_name: str) -> str | None:
    try:
        return ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _safe_delete_table(ddb: Any, table_name: str) -> None:
    # A table restored via RestoreTableToPointInTime can stay CREATING, and refuse DeleteTable
    # with ResourceInUseException, for several minutes.
    deadline = time.monotonic() + 900
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
