"""transact-write-items-token-replay-bills-exact-capacity-for-item-size."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "transact-write-items-token-replay-bills-exact-capacity-for-item-size"
GROUP = 'capacity'
SERVICES = ['dynamodb']

_PK_NAME = 'pk'
_VAL_NAME = 'payload'
_TARGET_BYTES = 1500  # within (1024, 2048]: 2 base write units; within (0, 4096]: 1 base read unit


def _item(pk_value: str) -> dict:
    overhead = (
        len(_PK_NAME.encode('utf-8')) + len(pk_value.encode('utf-8')) + len(_VAL_NAME.encode('utf-8'))
    )
    pad_len = _TARGET_BYTES - overhead
    return {_PK_NAME: {'S': pk_value}, _VAL_NAME: {'S': 'x' * pad_len}}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ~1.5KB TransactWriteItems Put bills 4 write capacity units; a same-token replay of it
    bills 2 read capacity units, a transactional read of the stored item, and no write capacity."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': _PK_NAME, 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': _PK_NAME, 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    item = _item('txn-item')

    def put_tx(client_token):
        return ddb.transact_write_items(
            ClientRequestToken=client_token,
            ReturnConsumedCapacity='INDEXES',
            TransactItems=[{'Put': {
                'TableName': table,
                'Item': item,
                'ConditionExpression': f'attribute_not_exists({_PK_NAME})',
            }}],
        )['ConsumedCapacity'][0]

    def stored():
        return ddb.get_item(TableName=table, Key={_PK_NAME: item[_PK_NAME]}, ConsistentRead=True)['Item']

    token = str(uuid.uuid4())

    # --- first use: a write of the committed item ---
    first = put_tx(token)
    assert first.get('WriteCapacityUnits') == 4.0, (
        f'a ~1.5KB TransactWriteItems Put billed WriteCapacityUnits {first.get("WriteCapacityUnits")!r}, '
        f'expected 4.0'
    )
    assert first.get('ReadCapacityUnits', 0) == 0, (
        f'the first use of a token billed ReadCapacityUnits {first.get("ReadCapacityUnits")!r}, expected none'
    )
    assert first['CapacityUnits'] == 4.0, f'total CapacityUnits was {first["CapacityUnits"]!r}, expected 4.0'
    assert stored() == item, f'the committed item is {stored()!r}, expected {item!r}'

    # --- same-token replay: a read of the same item, not a re-execution of the write ---
    replay = put_tx(token)
    assert replay.get('ReadCapacityUnits') == 2.0, (
        f'a same-token replay of a ~1.5KB TransactWriteItems billed ReadCapacityUnits '
        f'{replay.get("ReadCapacityUnits")!r}, expected 2.0'
    )
    assert replay.get('WriteCapacityUnits', 0) == 0, (
        f'the replay billed WriteCapacityUnits {replay.get("WriteCapacityUnits")!r}, expected none'
    )
    assert replay['CapacityUnits'] == 2.0, f'total CapacityUnits was {replay["CapacityUnits"]!r}, expected 2.0'
    assert stored() == item, (
        f'the item changed to {stored()!r} after a replay; a deduplicated replay must leave it '
        f'untouched'
    )

    # --- positive control: a FRESH token against a same-size item is a write again ---
    fresh_item = _item('txn-item-fresh')
    fresh = ddb.transact_write_items(
        ClientRequestToken=str(uuid.uuid4()),
        ReturnConsumedCapacity='INDEXES',
        TransactItems=[{'Put': {'TableName': table, 'Item': fresh_item}}],
    )['ConsumedCapacity'][0]
    assert fresh.get('WriteCapacityUnits') == 4.0, (
        f'a fresh token billed WriteCapacityUnits {fresh.get("WriteCapacityUnits")!r}, expected 4.0'
    )
    assert fresh.get('ReadCapacityUnits', 0) == 0, (
        f'a fresh token billed ReadCapacityUnits {fresh.get("ReadCapacityUnits")!r}, expected none'
    )
    assert ddb.get_item(
        TableName=table, Key={_PK_NAME: fresh_item[_PK_NAME]}, ConsistentRead=True
    )['Item'] == fresh_item, 'the fresh-token item was not committed as written'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
