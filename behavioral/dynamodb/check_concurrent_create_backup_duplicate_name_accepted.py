"""concurrent-create-backup-duplicate-name-accepted."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-create-backup-duplicate-name-accepted"
GROUP = "concurrency"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Eight concurrent CreateBackup calls on one table with the same BackupName all succeed:
    DynamoDB does not enforce BackupName uniqueness, and each racer gets a distinct BackupArn
    whose DescribeBackup reports the shared name."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-cbc-")
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
    # A freshly-created table's continuous backups (PITR plumbing) take a short while to finish
    # enabling; CreateBackup fails with ContinuousBackupsUnavailableException until that settles,
    # which would otherwise be mistaken for the BackupInUseException race this check targets.
    _poll_until(
        lambda: ddb.describe_continuous_backups(TableName=table_name)["ContinuousBackupsDescription"][
            "ContinuousBackupsStatus"
        ],
        lambda status: status == "ENABLED",
        timeout_s=120,
        interval_s=2,
    )

    concurrency = 8
    shared_backup_name = ctx.unique_name("sim2real-behav-cbc-bk-")
    barrier = threading.Barrier(concurrency)
    results: list[dict[str, Any]] = [None] * concurrency  # type: ignore[list-item]

    def _create(i: int) -> None:
        barrier.wait()
        try:
            resp = ddb.create_backup(TableName=table_name, BackupName=shared_backup_name)
            results[i] = {"ok": True, "arn": resp["BackupDetails"]["BackupArn"]}
        except Exception as exc:  # noqa: BLE001
            results[i] = {"ok": False, "code": _error_code_from_exc(exc)}

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(_create, range(concurrency)))

    for r in results:
        if r and r.get("ok"):
            arn = r["arn"]
            ctx.on_cleanup(lambda a=arn: _safe_delete_backup(ddb, a))

    failures = [r for r in results if r and not r["ok"]]
    successes = [r for r in results if r and r["ok"]]

    assert not failures, (
        f"expected all {concurrency} concurrent same-named CreateBackup calls on the same table "
        f"to succeed independently (real DynamoDB does not enforce BackupName uniqueness or "
        f"serialize concurrent backup creates at this concurrency), but {len(failures)} were "
        f"rejected: {[f['code'] for f in failures]!r}"
    )
    assert len(successes) == concurrency, (
        f"expected all {concurrency} racers to succeed independently, got {len(successes)}"
    )

    for s in successes:
        described = _poll_until(
            lambda arn=s["arn"]: ddb.describe_backup(BackupArn=arn)["BackupDescription"],
            lambda desc: desc["BackupDetails"]["BackupStatus"] in ("AVAILABLE", "CREATING"),
            timeout_s=60,
            interval_s=3,
        )
        assert described["BackupDetails"]["BackupName"] == shared_backup_name, (
            f"expected the independently-read backup name to be {shared_backup_name!r}, "
            f"got {described['BackupDetails']['BackupName']!r}"
        )
    distinct_arns = {s["arn"] for s in successes}
    assert len(distinct_arns) == len(successes), (
        f"expected {len(successes)} distinct backup ARNs, got {len(distinct_arns)} -- a "
        "duplicate ARN would mean two racers were silently collapsed into one backup"
    )


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
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) not in ("BackupNotFoundException", "BackupInUseException"):
            raise


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
