"""sse-with-a-kms-alias-reports-the-resolved-key-arn."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "sse-with-a-kms-alias-reports-the-resolved-key-arn"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


def _wait_active(ddb, table, deadline_s=240):
    """Poll DescribeTable until the table is ACTIVE with no index still mutating."""
    import time

    end = time.time() + deadline_s
    while time.time() < end:
        t = ddb.describe_table(TableName=table)['Table']
        busy = [i for i in t.get('GlobalSecondaryIndexes') or []
                if i.get('IndexStatus') != 'ACTIVE']
        if t['TableStatus'] == 'ACTIVE' and not busy:
            return t
        time.sleep(3)
    raise AssertionError(f'{table} never settled to ACTIVE within {deadline_s}s')


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A KMS alias may be supplied for the table key, but the description always reports the RESOLVED
    key ARN and never echoes the alias back."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    kms = ctx.client('kms')
    key_id = kms.create_key(Description=f'{table} table key')['KeyMetadata']['KeyId']
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    alias = f'alias/{table}'
    kms.create_alias(AliasName=alias, TargetKeyId=key_id)
    ctx.on_cleanup(lambda: kms.delete_alias(AliasName=alias))
    ddb.update_table(TableName=table,
                     SSESpecification={'Enabled': True, 'SSEType': 'KMS',
                                       'KMSMasterKeyId': alias})
    t = _wait_active(ddb, table)
    # Enabling SSE is ASYNCHRONOUS: real AWS reports Status UPDATING before ENABLED, so the
    # transition is part of the contract rather than a detail to wait out silently.
    first = (t.get('SSEDescription') or {}).get('Status')
    assert first in ('UPDATING', 'ENABLED'), (
        f'enabling SSE reports UPDATING then ENABLED, got {first!r}'
    )
    end = time.time() + 180
    sse = t.get('SSEDescription') or {}
    while sse.get('Status') != 'ENABLED' and time.time() < end:
        time.sleep(5)
        sse = ddb.describe_table(TableName=table)['Table'].get('SSEDescription') or {}
    assert sse.get('Status') == 'ENABLED', f'SSE must settle to ENABLED, got {sse}'
    assert sse.get('SSEType') == 'KMS', f'expected SSEType KMS, got {sse}'
    arn = sse.get('KMSMasterKeyArn') or ''
    assert arn.startswith('arn:aws:kms:'), f'expected a resolved KMS key ARN, got {arn!r}'
    assert 'alias/' not in arn, f'the description must report the key, never the alias: {arn!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
