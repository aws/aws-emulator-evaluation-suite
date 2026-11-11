"""restore-to-earliest-restorable-time-excludes-later-writes."""
from __future__ import annotations

import time
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-to-earliest-restorable-time-excludes-later-writes"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']

_SKEW_S = 120


def _poll_until(
    probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float,
    interval_s: float, description: str = 'condition',
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s, last value: {last!r}')


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, 'response', None)
    if not response:
        return None
    return response.get('Error', {}).get('Code')


def _enable_pitr_with_retry(ddb: Any, table_name: str, *, timeout_s: float = 60, interval_s: float = 2) -> Any:
    """A just-created table has continuous backups enabling in the background; retry the
    enable request until that settles."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ddb.update_continuous_backups(
                TableName=table_name,
                PointInTimeRecoverySpecification={'PointInTimeRecoveryEnabled': True},
            )
        except ClientError as exc:
            if _error_code_from_exc(exc) == 'ContinuousBackupsUnavailableException' and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _server_time(response: dict[str, Any]) -> datetime:
    """The server's clock at ``response``, from its HTTP Date header (one-second resolution)."""
    return parsedate_to_datetime(response['ResponseMetadata']['HTTPHeaders']['date'])


def _safe_delete_table(ddb: Any, table_name: str, timeout_s: float = 900.0) -> None:
    """A table still CREATING from a restore refuses DeleteTable; retry until it can go."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = _error_code_from_exc(exc)
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException' or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _remaining(ctx: Any, cap_s: float) -> float:
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Enabling PITR reports EarliestRestorableDateTime at the moment it was enabled and a
    LatestRestorableDateTime no earlier; a restore to that earliest time carries over the item
    written before it and excludes the item written after it.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_PointInTimeRecoveryDescription.html
    """
    ddb = ctx.client('dynamodb')
    source = ctx.unique_name('sim2real-behav-rpitr-early-src-')
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, source))
    ddb.create_table(
        TableName=source,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
    )
    _poll_until(
        lambda: ddb.describe_table(TableName=source)['Table']['TableStatus'],
        lambda s: s == 'ACTIVE',
        timeout_s=60, interval_s=2, description=f'{source} ACTIVE',
    )

    put_a = ddb.put_item(TableName=source, Item={'pk': {'S': 'item-a'}, 'val': {'S': 'before-restore-time'}})
    wrote_a_at = _server_time(put_a)

    # PITR is enabled a few seconds after the first write on the server's clock, so the earliest
    # restorable time lies clearly after it and a restore to that time must carry it over.
    _poll_until(
        lambda: _server_time(ddb.describe_table(TableName=source)),
        lambda now: now >= wrote_a_at + timedelta(seconds=5),
        timeout_s=_SKEW_S + 30, interval_s=1,
        description='the server clock passing the first write by five seconds',
    )
    enabled = _enable_pitr_with_retry(ddb, source)
    enabled_at = _server_time(enabled)
    pitr = _poll_until(
        lambda: ddb.describe_continuous_backups(TableName=source)['ContinuousBackupsDescription']
        ['PointInTimeRecoveryDescription'],
        lambda p: (p['PointInTimeRecoveryStatus'] == 'ENABLED' and 'EarliestRestorableDateTime' in p
                   and 'LatestRestorableDateTime' in p),
        timeout_s=90, interval_s=2, description='PITR ENABLED with both restorable date-times',
    )
    earliest = pitr['EarliestRestorableDateTime']
    latest = pitr['LatestRestorableDateTime']
    low, high = enabled_at - timedelta(seconds=_SKEW_S), enabled_at + timedelta(seconds=_SKEW_S)
    assert low <= earliest <= high, (
        f'EarliestRestorableDateTime {earliest.isoformat()} is not within {_SKEW_S} s of the '
        f'UpdateContinuousBackups response time {enabled_at.isoformat()}'
    )
    assert earliest <= latest, (
        f'LatestRestorableDateTime {latest.isoformat()} precedes EarliestRestorableDateTime '
        f'{earliest.isoformat()}'
    )

    # The second write lands a few seconds after the earliest restorable time on the server's
    # clock, so a restore to that time must exclude it.
    _poll_until(
        lambda: _server_time(ddb.describe_table(TableName=source)),
        lambda now: now >= max(earliest, wrote_a_at) + timedelta(seconds=5),
        timeout_s=_SKEW_S + 30, interval_s=1,
        description='the server clock passing the earliest restorable time by five seconds',
    )
    ddb.put_item(TableName=source, Item={'pk': {'S': 'item-b'}, 'val': {'S': 'after-restore-time'}})

    target = ctx.unique_name('sim2real-behav-rpitr-early-dst-')

    def _attempt_restore() -> dict[str, Any] | None:
        try:
            resp = ddb.restore_table_to_point_in_time(
                SourceTableName=source, TargetTableName=target, RestoreDateTime=earliest,
            )
        except ClientError as exc:
            if _error_code_from_exc(exc) in ('InvalidRestoreTimeException', 'PointInTimeRecoveryUnavailableException'):
                return None
            raise
        ctx.on_cleanup(lambda: _safe_delete_table(ddb, target))
        return resp

    restore_resp = _poll_until(
        _attempt_restore, lambda r: r is not None, timeout_s=90, interval_s=3,
        description='RestoreTableToPointInTime to EarliestRestorableDateTime accepted',
    )
    described = restore_resp['TableDescription']
    assert described['TableName'] == target, (
        f'RestoreTableToPointInTime described table {described["TableName"]!r}, expected {target!r}'
    )
    summary = described['RestoreSummary']
    assert summary['RestoreDateTime'] == earliest, (
        f'RestoreSummary.RestoreDateTime {summary["RestoreDateTime"]!r} is not the requested '
        f'EarliestRestorableDateTime {earliest!r}'
    )

    _poll_until(
        lambda: ddb.describe_table(TableName=target)['Table'],
        lambda t: t['TableStatus'] == 'ACTIVE',
        timeout_s=_remaining(ctx, 1500.0), interval_s=5, description=f'{target} ACTIVE',
    )

    item_a = ddb.get_item(TableName=target, Key={'pk': {'S': 'item-a'}}, ConsistentRead=True).get('Item')
    assert item_a == {'pk': {'S': 'item-a'}, 'val': {'S': 'before-restore-time'}}, (
        f'item written before the restore time restored as {item_a!r}'
    )
    item_b = ddb.get_item(TableName=target, Key={'pk': {'S': 'item-b'}}, ConsistentRead=True).get('Item')
    assert item_b is None, (
        f'item written after the restore time must be excluded from the restored table, got {item_b!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
