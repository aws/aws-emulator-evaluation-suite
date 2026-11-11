"""backup-lifecycle-create-describe-delete-404."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "backup-lifecycle-create-describe-delete-404"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBackup -> AVAILABLE, DescribeBackup reflects it, DeleteBackup removes it and a
    subsequent DescribeBackup 404s (BackupNotFoundException)."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-bk-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )

    backup_name = ctx.unique_name("sim2real-behav-bkname-")

    def _attempt_create_backup() -> dict[str, Any] | None:
        try:
            return ddb.create_backup(TableName=table_name, BackupName=backup_name)
        except Exception as exc:  # noqa: BLE001
            # A just-created table has continuous backups enabling in the background; a
            # CreateBackup issued too soon is rejected until that settles.
            if _error_code_from_exc(exc) == "ContinuousBackupsUnavailableException":
                return None
            raise

    create_resp = _poll_until(
        _attempt_create_backup, lambda resp: resp is not None, timeout_s=180, interval_s=5
    )
    backup_arn = create_resp["BackupDetails"]["BackupArn"]
    assert create_resp["BackupDetails"]["BackupName"] == backup_name

    described = _poll_until(
        lambda: ddb.describe_backup(BackupArn=backup_arn)["BackupDescription"],
        lambda desc: desc["BackupDetails"]["BackupStatus"] == "AVAILABLE",
        timeout_s=180,
        interval_s=3,
    )
    assert described["BackupDetails"]["BackupStatus"] == "AVAILABLE"
    assert described["BackupDetails"]["BackupType"] == "USER"
    assert described["SourceTableDetails"]["TableName"] == table_name

    listed_before = ddb.list_backups(TableName=table_name)["BackupSummaries"]
    matching_before = [b for b in listed_before if b["BackupArn"] == backup_arn]
    assert len(matching_before) == 1, f"expected {backup_arn} in ListBackups, got {listed_before}"
    assert matching_before[0]["BackupStatus"] == "AVAILABLE"

    delete_resp = ddb.delete_backup(BackupArn=backup_arn)
    assert delete_resp["BackupDescription"]["BackupDetails"]["BackupStatus"] == "DELETED"

    def _describe_after_delete() -> tuple[str, str | None]:
        try:
            resp = ddb.describe_backup(BackupArn=backup_arn)
            return resp["BackupDescription"]["BackupDetails"]["BackupStatus"], None
        except Exception as exc:  # noqa: BLE001
            code = _error_code_from_exc(exc)
            if code is None:
                raise
            return code, exc.response["Error"].get("Message", "")

    final_state, final_message = _poll_until(
        _describe_after_delete,
        lambda state: state[0] == "BackupNotFoundException",
        timeout_s=120,
        interval_s=3,
    )
    assert final_state == "BackupNotFoundException", final_state
    not_found = f"Backup not found: {backup_arn}"
    assert final_message == not_found, f"DescribeBackup message {final_message!r}, expected {not_found!r}"

    listed_after = ddb.list_backups(TableName=table_name)["BackupSummaries"]
    assert not any(b["BackupArn"] == backup_arn for b in listed_after), listed_after

    redelete_code, redelete_message = _expect_error_code(lambda: ddb.delete_backup(BackupArn=backup_arn))
    assert redelete_code == "BackupNotFoundException", redelete_code
    assert redelete_message == not_found, f"DeleteBackup message {redelete_message!r}, expected {not_found!r}"


def _safe_delete_table(ddb: Any, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _expect_error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        code = _error_code_from_exc(exc)
        if code is None:
            raise
        return code, exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected failure, call succeeded with {result!r}")


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
