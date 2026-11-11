"""create-backup-nonexistent-table."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-backup-nonexistent-table"
GROUP = 'errors'
SERVICES = ['dynamodb']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBackup on a nonexistent table fails with TableNotFoundException and AWS's exact message and
    lists no backup, DescribeTable confirms the table is absent, and CreateBackup on a real table
    succeeds."""
    ddb = ctx.client('dynamodb')

    real_table = ctx.unique_name('sim2real-behav-ddb-')
    ddb.create_table(
        TableName=real_table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, real_table))
    _wait_table_active(ddb, real_table)
    _wait_continuous_backups_enabled(ddb, real_table)

    real_backup_name = ctx.unique_name('sim2real-behav-bkp-')
    created = _create_backup_with_retry(ddb, real_table, real_backup_name)
    real_backup_arn = created['BackupDetails']['BackupArn']
    assert created['BackupDetails']['BackupStatus'] in ('CREATING', 'AVAILABLE'), (
        f'positive control: expected CreateBackup to succeed on a real table, got {created}'
    )
    ctx.on_cleanup(lambda: _delete_backup_ignore(ddb, real_backup_arn))

    missing_table = real_table + '-absent'
    code, message = _error(
        lambda: ddb.create_backup(TableName=missing_table, BackupName=ctx.unique_name('sim2real-behav-bkp-')))
    assert code == 'TableNotFoundException', f'expected TableNotFoundException, got {code}'
    expected_msg = f'Table not found: {missing_table}'
    assert message == expected_msg, f'expected {expected_msg!r}, got {message!r}'

    listed = ddb.list_backups(TableName=missing_table)['BackupSummaries']
    assert listed == [], f'expected no backups for a nonexistent table, got {listed}'

    describe_code, describe_msg = _error(lambda: ddb.describe_table(TableName=missing_table))
    assert describe_code == 'ResourceNotFoundException', (
        f'expected the target table to independently not exist, got {describe_code}'
    )
    expected_describe_msg = f'Requested resource not found: Table: {missing_table} not found'
    assert describe_msg == expected_describe_msg, (
        f'expected {expected_describe_msg!r}, got {describe_msg!r}'
    )


def _error(fn):
    """The (Code, Message) of a call real AWS refuses. RAISES on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'real AWS refuses this call, but it SUCCEEDED and returned {result!r}')


def _create_backup_with_retry(ddb, table_name, backup_name, *, timeout_s=120.0, interval_s=5.0):
    # Immediately after a table becomes ACTIVE, its continuous-backups
    # infrastructure can still be settling, which makes CreateBackup
    # transiently reject with ContinuousBackupsUnavailableException. Retry
    # within a bound instead of treating this as a hard failure.
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ddb.create_backup(TableName=table_name, BackupName=backup_name)
        except ClientError as err:
            if err.response['Error']['Code'] != 'ContinuousBackupsUnavailableException':
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f'CreateBackup still unavailable after {timeout_s}s: {last_err}')


def _wait_table_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)['Table']
        if desc['TableStatus'] == 'ACTIVE':
            return desc
        time.sleep(interval_s)
    raise AssertionError(f'table {table_name} never became ACTIVE')


def _wait_continuous_backups_enabled(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_continuous_backups(TableName=table_name)['ContinuousBackupsDescription']
        if desc['ContinuousBackupsStatus'] == 'ENABLED':
            return desc
        time.sleep(interval_s)
    raise AssertionError(f'continuous backups for {table_name} never became ENABLED')


def _delete_table_ignore(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _delete_backup_ignore(ddb, backup_arn):
    try:
        ddb.delete_backup(BackupArn=backup_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "BackupNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
