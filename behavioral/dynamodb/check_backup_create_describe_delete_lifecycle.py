"""backup-create-describe-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "backup-create-describe-delete-lifecycle"
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


def _error(fn):
    """The (Code, Message) of a call real AWS refuses. RAISES on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'real AWS refuses this call, but it SUCCEEDED and returned {result!r}')


def _absent_ok(fn, absent_code):
    """Teardown for a resource the check itself may already have deleted: only `absent_code`
    is tolerated, any other failure still surfaces."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != absent_code:
            raise


def _wait_continuous_backups_ready(ddb, name, timeout_s=90):
    return _poll_until(
        lambda: ddb.describe_continuous_backups(TableName=name)['ContinuousBackupsDescription'],
        lambda d: d['ContinuousBackupsStatus'] == 'ENABLED',
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f'continuous backups ready for {name}',
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A backup created for a table becomes describable/listable and is removed
    (404) after DeleteBackup. Exercises CreateBackup, DescribeBackup,
    DeleteBackup, ListBackups."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    _wait_continuous_backups_ready(ddb, t)

    backup_name = ctx.unique_name('sim2real-behav-bkp-')
    resp = ddb.create_backup(TableName=t, BackupName=backup_name)
    arn = resp['BackupDetails']['BackupArn']
    ctx.on_cleanup(lambda: _absent_ok(lambda: ddb.delete_backup(BackupArn=arn), 'BackupNotFoundException'))
    assert resp['BackupDetails']['BackupStatus'] in ('CREATING', 'AVAILABLE'), (
        f"expected CreateBackup status CREATING or AVAILABLE, got {resp['BackupDetails']['BackupStatus']}"
    )

    desc = _poll_until(
        lambda: ddb.describe_backup(BackupArn=arn)['BackupDescription']['BackupDetails'],
        lambda d: d['BackupStatus'] == 'AVAILABLE',
        timeout_s=90,
        interval_s=2.0,
        description='backup AVAILABLE',
    )
    assert desc['BackupStatus'] == 'AVAILABLE', f"expected AVAILABLE, got {desc['BackupStatus']}"
    assert desc['BackupName'] == backup_name, f"expected {backup_name}, got {desc['BackupName']}"

    listed = ddb.list_backups(TableName=t)['BackupSummaries']
    assert any(b['BackupArn'] == arn for b in listed), f'expected {arn} in ListBackups, got {listed}'

    ddb.delete_backup(BackupArn=arn)

    not_found_msg = f'Backup not found: {arn}'
    code, message = _error(lambda: ddb.describe_backup(BackupArn=arn))
    assert code == 'BackupNotFoundException', f'expected BackupNotFoundException, got {code}'
    assert message == not_found_msg, f'expected {not_found_msg!r}, got {message!r}'

    listed_after = ddb.list_backups(TableName=t)['BackupSummaries']
    assert not any(b['BackupArn'] == arn for b in listed_after), (
        f'expected {arn} absent from ListBackups after delete, got {listed_after}'
    )

    redelete_code, redelete_msg = _error(lambda: ddb.delete_backup(BackupArn=arn))
    assert redelete_code == 'BackupNotFoundException', (
        f'expected a second DeleteBackup on the now-deleted backup to also 404, got {redelete_code}'
    )
    assert redelete_msg == not_found_msg, f'expected {not_found_msg!r}, got {redelete_msg!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
