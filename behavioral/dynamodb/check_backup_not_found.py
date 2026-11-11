"""backup-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "backup-not-found"
GROUP = 'errors'
SERVICES = ['dynamodb']


def _error(fn):
    """The (Code, Message) of a call real AWS refuses. RAISES on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected a ClientError, but the call succeeded and returned {result!r}')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeBackup and DeleteBackup for a syntactically well-formed but
    unknown backup ARN both return BackupNotFoundException."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    table_arn = ddb.describe_table(TableName=t)['Table']['TableArn']
    fake_backup_arn = f'{table_arn}/backup/01700000000000-aaaaaaaa'

    expected_msg = f'Backup not found: {fake_backup_arn}'

    describe_code, describe_msg = _error(lambda: ddb.describe_backup(BackupArn=fake_backup_arn))
    assert describe_code == 'BackupNotFoundException', f'expected BackupNotFoundException, got {describe_code}'
    assert describe_msg == expected_msg, f'DescribeBackup message: expected {expected_msg!r}, got {describe_msg!r}'

    delete_code, delete_msg = _error(lambda: ddb.delete_backup(BackupArn=fake_backup_arn))
    assert delete_code == 'BackupNotFoundException', f'expected BackupNotFoundException, got {delete_code}'
    assert delete_msg == expected_msg, f'DeleteBackup message: expected {expected_msg!r}, got {delete_msg!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
