"""restore-table-from-backup-sse-override-uses-customer-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-table-from-backup-sse-override-uses-customer-key"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _wait_table_settled(ddb, name, timeout_s=240):
    def probe():
        t = ddb.describe_table(TableName=name)['Table']
        sse = t.get('SSEDescription') or {}
        if t['TableStatus'] == 'ACTIVE' and sse.get('Status') != 'UPDATING':
            return t
        return None
    return _poll_until(probe, lambda t: t is not None, timeout_s=timeout_s, description=f'{name} ACTIVE with SSE settled')


def _safe_delete_table(ddb, name, timeout_s=240.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=name)
            return
        except ClientError as exc:
            code = exc.response['Error']['Code']
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException' or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _safe_delete_backup(ddb, backup_arn):
    try:
        ddb.delete_backup(BackupArn=backup_arn)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'BackupNotFoundException':
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RestoreTableFromBackup with SSESpecificationOverride re-encrypts the restored table
    with the given customer managed KMS key, reported in SSEDescription.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_RestoreTableFromBackup.html
    """
    start = time.monotonic()

    def _remaining_budget(total=1700.0, floor=30.0):
        return max(floor, total - (time.monotonic() - start))

    ddb = ctx.client('dynamodb')
    kms = ctx.client('kms')

    source = ctx.unique_name('sim2real-behav-rfb-sse-src-')
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, source))
    ddb.create_table(
        TableName=source,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    _wait_table_settled(ddb, source)
    source_sse = ddb.describe_table(TableName=source)['Table'].get('SSEDescription')
    assert source_sse is None, f'expected the source table to use the AWS owned key, got SSEDescription {source_sse!r}'

    def _attempt_create_backup():
        try:
            backup_name = ctx.unique_name('sim2real-behav-rfb-sse-bk-')
            return ddb.create_backup(TableName=source, BackupName=backup_name)
        except ClientError as exc:
            if exc.response['Error']['Code'] == 'ContinuousBackupsUnavailableException':
                return None
            raise

    backup_arn = _poll_until(
        _attempt_create_backup, lambda r: r is not None, timeout_s=90, interval_s=5,
        description='CreateBackup accepted',
    )['BackupDetails']['BackupArn']
    ctx.on_cleanup(lambda: _safe_delete_backup(ddb, backup_arn))
    _poll_until(
        lambda: ddb.describe_backup(BackupArn=backup_arn)['BackupDescription']['BackupDetails']['BackupStatus'],
        lambda s: s == 'AVAILABLE',
        timeout_s=120,
        description='backup AVAILABLE',
    )

    cmk = kms.create_key(
        Description=f'{source} restore override key',
        Tags=[{'TagKey': 'sim2real', 'TagValue': CHECK}],
    )['KeyMetadata']
    cmk_id = cmk['KeyId']
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=cmk_id, PendingWindowInDays=7))

    target = ctx.unique_name('sim2real-behav-rfb-sse-dst-')
    ddb.restore_table_from_backup(
        TargetTableName=target,
        BackupArn=backup_arn,
        SSESpecificationOverride={'Enabled': True, 'SSEType': 'KMS', 'KMSMasterKeyId': cmk_id},
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, target))
    described = _wait_table_settled(ddb, target, timeout_s=_remaining_budget())

    sse = described.get('SSEDescription') or {}
    assert sse.get('Status') == 'ENABLED', f'expected SSEDescription.Status ENABLED, got {sse!r}'
    assert sse.get('SSEType') == 'KMS', f'expected SSEDescription.SSEType KMS, got {sse!r}'
    assert sse.get('KMSMasterKeyArn') == cmk['Arn'], (
        f'expected SSESpecificationOverride key {cmk["Arn"]!r} reported as the table key ARN, got {sse.get("KMSMasterKeyArn")!r}'
    )
    key_meta = kms.describe_key(KeyId=cmk_id)['KeyMetadata']
    assert key_meta['KeyManager'] == 'CUSTOMER', (
        f'expected the override key to resolve to a CUSTOMER managed key, got KeyManager {key_meta["KeyManager"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
