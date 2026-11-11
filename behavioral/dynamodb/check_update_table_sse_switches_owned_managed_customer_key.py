"""update-table-sse-switches-owned-managed-customer-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-sse-switches-owned-managed-customer-key"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


def _wait_sse_settled(ddb, table, deadline_s=240):
    """Poll DescribeTable until the table is ACTIVE and SSEDescription (if any) is not UPDATING."""
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        t = ddb.describe_table(TableName=table)['Table']
        sse = t.get('SSEDescription') or {}
        if t['TableStatus'] == 'ACTIVE' and sse.get('Status') != 'UPDATING':
            return t
        time.sleep(3)
    raise AssertionError(f'{table} never settled after an SSE change within {deadline_s}s')


def _safe_delete_table(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTable SSESpecification moves a table between the AWS owned key, the AWS
    managed key and a customer managed key, and DescribeTable reflects each once ACTIVE.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html
    """
    ddb = ctx.client('dynamodb')
    kms = ctx.client('kms')

    table_name = ctx.unique_name('sim2real-behav-ddb-sse-switch-')
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ddb.get_waiter('table_exists').wait(TableName=table_name, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})

    owned = ddb.describe_table(TableName=table_name)['Table'].get('SSEDescription')
    assert owned is None, f'a table created with no SSESpecification uses the AWS owned key and reports no SSEDescription, got {owned!r}'

    ddb.update_table(TableName=table_name, SSESpecification={'Enabled': True})
    managed = _wait_sse_settled(ddb, table_name).get('SSEDescription') or {}
    assert managed.get('Status') == 'ENABLED', f'expected SSEDescription.Status ENABLED, got {managed}'
    assert managed.get('SSEType') == 'KMS', f'expected SSEDescription.SSEType KMS, got {managed}'
    managed_arn = managed.get('KMSMasterKeyArn') or ''
    managed_key_id = managed_arn.rsplit('/', 1)[-1]
    managed_meta = kms.describe_key(KeyId=managed_key_id)['KeyMetadata']
    assert managed_meta['KeyManager'] == 'AWS', (
        f'enabling SSE with no key id must resolve to an AWS managed key, got KeyManager {managed_meta["KeyManager"]!r}'
    )
    managed_aliases = {a['AliasName'] for a in kms.list_aliases(KeyId=managed_key_id)['Aliases']}
    assert 'alias/aws/dynamodb' in managed_aliases, (
        f'expected the AWS managed key to carry alias/aws/dynamodb, got {sorted(managed_aliases)!r}'
    )

    cmk = kms.create_key(
        Description=f'{table_name} customer managed table key',
        Tags=[{'TagKey': 'sim2real', 'TagValue': CHECK}],
    )['KeyMetadata']
    cmk_id = cmk['KeyId']
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=cmk_id, PendingWindowInDays=7))
    assert cmk['KeyManager'] == 'CUSTOMER', f'expected a freshly created key to be CUSTOMER managed, got {cmk["KeyManager"]!r}'

    ddb.update_table(
        TableName=table_name,
        SSESpecification={'Enabled': True, 'SSEType': 'KMS', 'KMSMasterKeyId': cmk_id},
    )
    customer = _wait_sse_settled(ddb, table_name).get('SSEDescription') or {}
    assert customer.get('Status') == 'ENABLED', f'expected SSEDescription.Status ENABLED, got {customer}'
    assert customer.get('SSEType') == 'KMS', f'expected SSEDescription.SSEType KMS, got {customer}'
    customer_arn = customer.get('KMSMasterKeyArn') or ''
    assert customer_arn == cmk['Arn'], (
        f'expected the table key ARN to be the customer key just supplied {cmk["Arn"]!r}, got {customer_arn!r}'
    )
    customer_meta = kms.describe_key(KeyId=customer_arn.rsplit('/', 1)[-1])['KeyMetadata']
    assert customer_meta['KeyManager'] == 'CUSTOMER', (
        f'the key id supplied explicitly must resolve to a CUSTOMER managed key, got KeyManager {customer_meta["KeyManager"]!r}'
    )

    ddb.update_table(TableName=table_name, SSESpecification={'Enabled': False})
    back_to_owned = _wait_sse_settled(ddb, table_name).get('SSEDescription')
    assert back_to_owned is None, (
        f'disabling SSE must return the table to the AWS owned key and report no SSEDescription, got {back_to_owned!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
