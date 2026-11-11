"""restore-from-backup-drops-tags-stream-ttl-deletion-protection."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-from-backup-drops-tags-stream-ttl-deletion-protection"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']

_KEY_SCHEMA = [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}]
_ATTR_DEFS = [
    {'AttributeName': 'pk', 'AttributeType': 'S'},
    {'AttributeName': 'sk', 'AttributeType': 'S'},
    {'AttributeName': 'gsipk', 'AttributeType': 'S'},
    {'AttributeName': 'gsisk', 'AttributeType': 'S'},
    {'AttributeName': 'lsisk', 'AttributeType': 'S'},
]
_GSI = {
    'IndexName': 'gsi1',
    'KeySchema': [{'AttributeName': 'gsipk', 'KeyType': 'HASH'}, {'AttributeName': 'gsisk', 'KeyType': 'RANGE'}],
    'Projection': {'ProjectionType': 'ALL'},
}
_LSI = {
    'IndexName': 'lsi1',
    'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsisk', 'KeyType': 'RANGE'}],
    'Projection': {'ProjectionType': 'ALL'},
}
_TTL_ATTR = 'expiresAt'


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
        busy = [i for i in (t.get('GlobalSecondaryIndexes') or []) + (t.get('LocalSecondaryIndexes') or [])
                if i.get('IndexStatus') not in (None, 'ACTIVE')]
        return t if t['TableStatus'] == 'ACTIVE' and not busy else None
    return _poll_until(probe, lambda t: t is not None, timeout_s=timeout_s, description=f'{name} ACTIVE with settled indexes')


def _disable_deletion_protection(ddb, name):
    try:
        ddb.update_table(TableName=name, DeletionProtectionEnabled=False)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            raise


def _safe_delete_table(ddb, name, timeout_s=240.0):
    """Disable deletion protection (idempotent), then delete; retry while CREATING/UPDATING."""
    _disable_deletion_protection(ddb, name)
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


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A table restored via RestoreTableFromBackup carries the source's key schema, GSIs
    and LSIs, but not its tags, stream specification, TTL setting or deletion protection.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_RestoreTableFromBackup.html
    """
    start = time.monotonic()

    def _remaining_budget(total=1700.0, floor=30.0):
        return max(floor, total - (time.monotonic() - start))

    ddb = ctx.client('dynamodb')
    source = ctx.unique_name('sim2real-behav-rfb-settings-src-')
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, source))
    ddb.create_table(
        TableName=source,
        KeySchema=_KEY_SCHEMA,
        AttributeDefinitions=_ATTR_DEFS,
        BillingMode='PAY_PER_REQUEST',
        GlobalSecondaryIndexes=[_GSI],
        LocalSecondaryIndexes=[_LSI],
        StreamSpecification={'StreamEnabled': True, 'StreamViewType': 'NEW_AND_OLD_IMAGES'},
        DeletionProtectionEnabled=True,
        Tags=[{'Key': 'sim2real', 'Value': CHECK}, {'Key': 'team', 'Value': 'payments'}],
    )
    source_described = _wait_table_settled(ddb, source)
    assert source_described['StreamSpecification']['StreamEnabled'] is True, (
        f"expected the source table's stream enabled, got {source_described.get('StreamSpecification')!r}"
    )
    assert source_described['DeletionProtectionEnabled'] is True, (
        f"expected the source table's deletion protection on, got "
        f"{source_described.get('DeletionProtectionEnabled')!r}"
    )

    ddb.update_time_to_live(
        TableName=source, TimeToLiveSpecification={'Enabled': True, 'AttributeName': _TTL_ATTR}
    )
    _poll_until(
        lambda: ddb.describe_time_to_live(TableName=source)['TimeToLiveDescription']['TimeToLiveStatus'],
        lambda s: s == 'ENABLED',
        timeout_s=90,
        description='source TTL ENABLED',
    )

    def _attempt_create_backup():
        try:
            backup_name = ctx.unique_name('sim2real-behav-rfb-settings-bk-')
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

    target = ctx.unique_name('sim2real-behav-rfb-settings-dst-')
    ddb.restore_table_from_backup(TargetTableName=target, BackupArn=backup_arn)
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, target))
    described = _wait_table_settled(ddb, target, timeout_s=_remaining_budget())

    assert described['KeySchema'] == _KEY_SCHEMA, (
        f'expected the restored table to carry the source key schema {_KEY_SCHEMA!r}, got {described["KeySchema"]!r}'
    )
    gsi_schemas = {i['IndexName']: i['KeySchema'] for i in described.get('GlobalSecondaryIndexes') or []}
    assert gsi_schemas.get('gsi1') == _GSI['KeySchema'], (
        f'expected the GSI to carry over with schema {_GSI["KeySchema"]!r}, got {gsi_schemas!r}'
    )
    lsi_schemas = {i['IndexName']: i['KeySchema'] for i in described.get('LocalSecondaryIndexes') or []}
    assert lsi_schemas.get('lsi1') == _LSI['KeySchema'], (
        f'expected the LSI to carry over with schema {_LSI["KeySchema"]!r}, got {lsi_schemas!r}'
    )

    target_arn = described['TableArn']
    target_tags = ddb.list_tags_of_resource(ResourceArn=target_arn).get('Tags', [])
    assert target_tags == [], (
        f'expected the restored table to carry no tags from the source, got {target_tags!r}'
    )

    stream_spec = described.get('StreamSpecification') or {}
    assert stream_spec.get('StreamEnabled', False) is False, (
        f'expected the restored table to not inherit the source stream specification, got {stream_spec!r}'
    )
    assert 'LatestStreamArn' not in described, (
        f'expected no stream ARN on the restored table, got {described.get("LatestStreamArn")!r}'
    )

    target_ttl = ddb.describe_time_to_live(TableName=target)['TimeToLiveDescription']
    assert target_ttl['TimeToLiveStatus'] == 'DISABLED', (
        f'expected TTL to not carry over to the restored table, got {target_ttl!r}'
    )

    assert described.get('DeletionProtectionEnabled', False) is False, (
        f'expected deletion protection to not carry over to the restored table, got {described.get("DeletionProtectionEnabled")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
