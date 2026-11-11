"""restore-backup-name-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-backup-name-conflict"
GROUP = 'errors'
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


def _error(fn):
    """Call fn() and return its error code and message; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get('Error', {})
        return error.get('Code'), error.get('Message')
    raise AssertionError(f'expected rejection, but the call SUCCEEDED and returned {result!r}')


def _delete_table_past_tag_update(ddb, name, timeout_s=600):
    """DeleteTable is refused with ResourceInUseException while the restore or a tag update is
    still in progress; retry to a deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=name)
            return
        except ClientError as exc:
            if exc.response['Error']['Code'] == 'ResourceNotFoundException':
                return
            if exc.response['Error']['Code'] != 'ResourceInUseException' or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _delete_backup(ddb, backup_arn, timeout_s=300):
    """DeleteBackup is refused with BackupInUseException while a restore from it is in progress;
    retry to a deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_backup(BackupArn=backup_arn)
            return
        except ClientError as exc:
            if exc.response['Error']['Code'] == 'BackupNotFoundException':
                return
            if exc.response['Error']['Code'] != 'BackupInUseException' or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _wait_continuous_backups_ready(ddb, name, timeout_s=90):
    return _poll_until(
        lambda: ddb.describe_continuous_backups(TableName=name)['ContinuousBackupsDescription'],
        lambda d: d['ContinuousBackupsStatus'] == 'ENABLED',
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f'continuous backups ready for {name}',
    )


def _simple_table(ctx, ddb):
    name = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreTableFromBackup onto an existing ACTIVE table name fails with
    TableAlreadyExistsException and leaves that table untouched; a free name restores fine."""
    ddb = ctx.client('dynamodb')
    source = _simple_table(ctx, ddb)
    ddb.put_item(TableName=source, Item={'pk': {'S': 'seed'}, 'v': {'S': 'seed-data'}})
    other_active_name = _simple_table(ctx, ddb)  # already-ACTIVE table whose name we'll collide with
    ddb.put_item(TableName=other_active_name, Item={'pk': {'S': 'sentinel'}, 'v': {'S': 'untouched'}})
    _wait_continuous_backups_ready(ddb, source)

    backup_arn = ddb.create_backup(TableName=source, BackupName=ctx.unique_name('sim2real-behav-bkp-'))['BackupDetails']['BackupArn']
    ctx.on_cleanup(lambda: _delete_backup(ddb, backup_arn))
    _poll_until(
        lambda: ddb.describe_backup(BackupArn=backup_arn)['BackupDescription']['BackupDetails']['BackupStatus'],
        lambda s: s == 'AVAILABLE',
        timeout_s=90,
        interval_s=2.0,
        description='backup AVAILABLE',
    )

    # Positive control: proves the later rejection is about the name collision, not the backup.
    free_name = ctx.unique_name('sim2real-behav-restored-')
    ddb.restore_table_from_backup(TargetTableName=free_name, BackupArn=backup_arn)
    ctx.on_cleanup(lambda: _delete_table_past_tag_update(ddb, free_name))
    ddb.get_waiter('table_exists').wait(TableName=free_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.tag_resource(
        ResourceArn=ddb.describe_table(TableName=free_name)['Table']['TableArn'],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    control_item = ddb.get_item(TableName=free_name, Key={'pk': {'S': 'seed'}}, ConsistentRead=True)
    assert control_item.get('Item', {}).get('v', {}).get('S') == 'seed-data', (
        f'positive control: restoring to a free name should carry the source data, got {control_item!r}')

    before = ddb.describe_table(TableName=other_active_name)['Table']

    code, message = _error(lambda: ddb.restore_table_from_backup(TargetTableName=other_active_name, BackupArn=backup_arn))
    assert code == 'TableAlreadyExistsException', f'expected TableAlreadyExistsException, got {code}'
    expected = f'Table already exists: {other_active_name}'
    assert message == expected, f'unexpected message {message!r}'

    # The collision target keeps its identity, status and data (no partial restore).
    after = ddb.describe_table(TableName=other_active_name)['Table']
    assert after['TableStatus'] == 'ACTIVE', f'other_active table status changed to {after["TableStatus"]!r} after rejected restore'
    assert after['TableArn'] == before['TableArn'], 'other_active table was replaced (ARN changed) by the rejected restore'
    assert after['CreationDateTime'] == before['CreationDateTime'], 'other_active table was recreated (CreationDateTime changed) by the rejected restore'
    sentinel = ddb.get_item(TableName=other_active_name, Key={'pk': {'S': 'sentinel'}}, ConsistentRead=True)
    assert sentinel.get('Item', {}).get('v', {}).get('S') == 'untouched', f'expected original sentinel item intact, got {sentinel!r}'
    leaked = ddb.get_item(TableName=other_active_name, Key={'pk': {'S': 'seed'}}, ConsistentRead=True)
    assert 'Item' not in leaked, f'source table data leaked into the collision target despite the rejection: {leaked!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
