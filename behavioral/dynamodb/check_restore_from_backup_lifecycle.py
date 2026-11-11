"""restore-from-backup-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-from-backup-lifecycle"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _teardown(undo, *not_found):
    """A cleanup running ``undo()`` that returns only on the resource's own not-found codes."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response['Error']['Code'] in not_found:
                return
            raise

    return run_undo


def _error_detail(fn):
    """The (code, message) a rejected call returned; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get('Error', {})
        return error.get('Code'), error.get('Message')
    raise AssertionError(f'expected a rejection, the call succeeded: {result!r}')


def _wait_continuous_backups_ready(ddb, name, timeout_s=90):
    return _poll_until(
        lambda: ddb.describe_continuous_backups(TableName=name)['ContinuousBackupsDescription'],
        lambda d: d['ContinuousBackupsStatus'] == 'ENABLED',
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f'continuous backups ready for {name}',
    )


def _wait_table_deleted(ddb, name, timeout_s=90):
    def probe():
        try:
            return ddb.describe_table(TableName=name)['Table']['TableStatus']
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                return 'GONE'
            raise
    _poll_until(probe, lambda s: s == 'GONE', timeout_s=timeout_s, interval_s=1.0, description=f'table {name} deleted')


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RestoreTableFromBackup produces a new independently describable and
    deletable table. Exercises RestoreTableFromBackup, DescribeTable,
    DeleteTable."""
    start = time.monotonic()

    def _remaining_budget(total: float = 1500.0, floor: float = 30.0) -> float:
        return max(floor, total - (time.monotonic() - start))

    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=t), 'ResourceNotFoundException'))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=t, Item={'pk': {'S': 'seed'}, 'v': {'S': '1'}})
    _wait_continuous_backups_ready(ddb, t)

    backup_name = ctx.unique_name('sim2real-behav-bkp-')
    arn = ddb.create_backup(TableName=t, BackupName=backup_name)['BackupDetails']['BackupArn']
    ctx.on_cleanup(_teardown(lambda: ddb.delete_backup(BackupArn=arn), 'BackupNotFoundException'))
    _poll_until(
        lambda: ddb.describe_backup(BackupArn=arn)['BackupDescription']['BackupDetails']['BackupStatus'],
        lambda s: s == 'AVAILABLE',
        timeout_s=90,
        interval_s=2.0,
        description='backup AVAILABLE',
    )

    target_name = ctx.unique_name('sim2real-behav-restored-')
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=target_name),
                             'ResourceNotFoundException'))
    restore_resp = ddb.restore_table_from_backup(TargetTableName=target_name, BackupArn=arn)
    restore_status = restore_resp['TableDescription']['TableStatus']
    assert restore_status in ('CREATING', 'ACTIVE'), (
        f"expected RestoreTableFromBackup's own response to report CREATING or ACTIVE, got {restore_status!r}"
    )
    restore_source_arn = restore_resp['TableDescription']['RestoreSummary']['SourceBackupArn']
    assert restore_source_arn == arn, (
        f'expected RestoreSummary.SourceBackupArn {arn!r}, got {restore_source_arn!r}'
    )

    # Restore latency varies; the ACTIVE wait is bounded by the runner's remaining time, less
    # a reserve for the delete leg below, so a restore that never finishes fails here.
    budget = _remaining_budget()
    time_left = ctx.time_left()
    if time_left is not None:
        budget = max(5.0, min(budget, time_left - 120.0))
    try:
        table = _poll_until(
            lambda: ddb.describe_table(TableName=target_name)['Table'],
            lambda tbl: tbl['TableStatus'] == 'ACTIVE',
            timeout_s=budget,
            interval_s=3.0,
            description=f'table {target_name} ACTIVE',
        )
    except AssertionError:
        # The poll's own deadline and this immediate re-read are not atomic: the restore can
        # cross into ACTIVE in that gap (observed on real AWS), so a fresh ACTIVE here is the
        # slow-but-correct case. Any other status fails: only ACTIVE is a finished restore.
        current = ddb.describe_table(TableName=target_name)['Table']
        assert current['TableStatus'] == 'ACTIVE', (
            f'expected the restored table {target_name!r} to reach ACTIVE within {budget:.0f}s, '
            f'got {current["TableStatus"]!r}'
        )
        table = current

    assert table['TableName'] == target_name, (
        f"expected the polled table's own name {target_name!r}, got {table['TableName']!r}"
    )
    described = ddb.describe_table(TableName=target_name)['Table']
    assert described['TableName'] == target_name, (
        f"expected DescribeTable to report {target_name!r}, got {described['TableName']!r}"
    )

    # Independently deletable without affecting the source table.
    ddb.delete_table(TableName=target_name)
    _wait_table_deleted(ddb, target_name)
    code, message = _error_detail(lambda: ddb.describe_table(TableName=target_name))
    assert code == 'ResourceNotFoundException', (
        f'expected DescribeTable on the deleted restored table to raise ResourceNotFoundException, got {code!r}'
    )
    expected_message = f'Requested resource not found: Table: {target_name} not found'
    assert message == expected_message, f'expected message {expected_message!r}, got {message!r}'
    mutate_code, mutate_message = _error_detail(
        lambda: ddb.put_item(TableName=target_name, Item={'pk': {'S': 'x'}}))
    assert mutate_code == 'ResourceNotFoundException', (
        f'expected PutItem against the deleted restored table to raise ResourceNotFoundException, got {mutate_code!r}'
    )
    assert mutate_message == 'Requested resource not found', (
        f"expected message 'Requested resource not found', got {mutate_message!r}"
    )
    source_status = ddb.describe_table(TableName=t)['Table']['TableStatus']
    assert source_status == 'ACTIVE', (
        f'expected the source table to remain ACTIVE after deleting the restored table, got {source_status!r}'
    )

    ddb.delete_backup(BackupArn=arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
