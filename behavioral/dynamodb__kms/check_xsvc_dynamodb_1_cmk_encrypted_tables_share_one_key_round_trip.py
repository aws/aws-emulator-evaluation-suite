"""xsvc-dynamodb-1-cmk-encrypted-tables-share-one-key-round-trip."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "xsvc-dynamodb-1-cmk-encrypted-tables-share-one-key-round-trip"
GROUP = 'sse_kms'
SERVICES = ['dynamodb', 'kms']

_KMS_TAGS = [{"TagKey": "sim2real", "TagValue": "dynamodb-sse-cmk"}]
_DDB_TAGS = [{"Key": "sim2real", "Value": "dynamodb-sse-cmk"}]


def _wait_active(ddb, table, deadline_s=240):
    """Poll DescribeTable until the table reports ACTIVE; return the description."""
    end = time.time() + deadline_s
    while time.time() < end:
        t = ddb.describe_table(TableName=table)['Table']
        if t['TableStatus'] == 'ACTIVE':
            return t
        time.sleep(3)
    raise AssertionError(f'{table} never reached ACTIVE within {deadline_s}s')


def _create_cmk_table(ctx, ddb, key_id):
    # The BARE KEY ID goes in, deliberately: reporting the full ARN back requires resolving the
    # id in KMS, which an echo of the input cannot fake.
    table = ctx.unique_name('sim2real-xsvc-ddbkms-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        SSESpecification={'Enabled': True, 'SSEType': 'KMS', 'KMSMasterKeyId': key_id},
        Tags=_DDB_TAGS,
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    return table


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Two DynamoDB tables encrypted with ONE customer-managed KMS key both serve reads and writes,
    both report that key's ARN resolved from the bare key id, and each keeps its own items.
    """
    kms = ctx.client('kms')
    ddb = ctx.client('dynamodb')
    token = uuid.uuid4().hex[:8]

    key = kms.create_key(Description=f'sim2real-xsvc-ddb-sse-shared-{token}',
                         KeyUsage='ENCRYPT_DECRYPT', Tags=_KMS_TAGS)['KeyMetadata']
    key_id, key_arn = key['KeyId'], key['Arn']
    # KMS has no immediate delete: 7 days is the minimum PendingWindowInDays. LIFO runs this
    # LAST, after both tables are gone.
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    first = _create_cmk_table(ctx, ddb, key_id)
    second = _create_cmk_table(ctx, ddb, key_id)

    for table in (first, second):
        sse = _wait_active(ddb, table).get('SSEDescription') or {}
        assert sse.get('Status') == 'ENABLED', f'{table}: SSE status {sse!r}, expected ENABLED'
        assert sse.get('SSEType') == 'KMS', f'{table}: SSEType {sse.get("SSEType")!r}, expected KMS'
        # key_id went in (see _create_cmk_table); the resolved full ARN must come back.
        assert sse.get('KMSMasterKeyArn') == key_arn, (
            f'{table}: was created on CMK id {key_id!r} and must report its resolved ARN '
            f'{key_arn!r}, got {sse.get("KMSMasterKeyArn")!r}'
        )

    body = f'payload-{token}|multibyte: 日本語 éü'
    for table in (first, second):
        ddb.put_item(TableName=table, Item={'pk': {'S': f'item-{table}'}, 'v': {'S': body},
                                             'n': {'N': '1'}})
        ddb.update_item(TableName=table, Key={'pk': {'S': f'item-{table}'}},
                        UpdateExpression='SET n = n + :one',
                        ExpressionAttributeValues={':one': {'N': '1'}})

    for table, other in ((first, second), (second, first)):
        got = ddb.get_item(TableName=table, Key={'pk': {'S': f'item-{table}'}},
                           ConsistentRead=True).get('Item')
        assert got == {'pk': {'S': f'item-{table}'}, 'v': {'S': body}, 'n': {'N': '2'}}, (
            f'{table}: a CMK-encrypted table did not round-trip its item byte-exact: {got!r}'
        )
        leaked = ddb.get_item(TableName=table, Key={'pk': {'S': f'item-{other}'}},
                              ConsistentRead=True).get('Item')
        assert leaked is None, (
            f'{table}: two tables sharing one CMK must not share items, but it returned '
            f'{other}\'s item {leaked!r}'
        )

    state = kms.describe_key(KeyId=key_id)['KeyMetadata']['KeyState']
    assert state == 'Enabled', f'the shared CMK should still be Enabled, got {state!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
