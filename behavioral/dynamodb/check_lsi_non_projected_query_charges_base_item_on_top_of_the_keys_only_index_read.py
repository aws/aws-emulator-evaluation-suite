"""lsi-non-projected-query-charges-base-item-on-top-of-the-keys-only-index-read."""
from __future__ import annotations

import math

from behavioral_harness import tags

CHECK = "lsi-non-projected-query-charges-base-item-on-top-of-the-keys-only-index-read"
GROUP = 'lsi'
SERVICES = ['dynamodb']

_PAYLOAD = 'x' * 8000

# A KEYS_ONLY LSI entry carries only the base table's key and the index's own sort key.
_INDEX_ONLY_ITEM_BYTES = (len('pk') + len('P')) + (len('sk') + len('S1')) + (len('lsk') + len('L1'))
_BASE_ITEM_BYTES = _INDEX_ONLY_ITEM_BYTES + len('payload') + len(_PAYLOAD)

_INDEX_ONLY_RCU = math.ceil(_INDEX_ONLY_ITEM_BYTES / 4096)
_BASE_RCU = math.ceil(_BASE_ITEM_BYTES / 4096)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query on a KEYS_ONLY LSI that names a non-projected attribute fetches the base item and
    bills its 4 KB-rounded size in addition to the index-only read; naming a projected attribute
    does not.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LSI.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-lsisize-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'S'},
        ],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})

    ddb.put_item(TableName=table, Item={
        'pk': {'S': 'P'}, 'sk': {'S': 'S1'}, 'lsk': {'S': 'L1'}, 'payload': {'S': _PAYLOAD},
    })

    # Positive control: no ProjectionExpression at all stays index-only.
    bare = ddb.query(TableName=table, IndexName='lsi1', KeyConditionExpression='pk = :p',
                      ExpressionAttributeValues={':p': {'S': 'P'}}, ConsistentRead=True,
                      ReturnConsumedCapacity='INDEXES')
    assert set(bare['Items'][0]) == {'pk', 'sk', 'lsk'}, (
        f'a KEYS_ONLY LSI with no ProjectionExpression must return only the keys, got '
        f'{sorted(bare["Items"][0])!r}'
    )
    bare_cc = bare['ConsumedCapacity']
    assert bare_cc['CapacityUnits'] == _INDEX_ONLY_RCU, (
        f'the index-only read of {_INDEX_ONLY_ITEM_BYTES!r} raw bytes must bill exactly '
        f'{_INDEX_ONLY_RCU!r} RCU, got {bare_cc["CapacityUnits"]!r}'
    )
    assert bare_cc['Table']['CapacityUnits'] == 0, (
        f'an index-only LSI read must charge the Table arm nothing, got {bare_cc["Table"]!r}'
    )
    assert bare_cc['LocalSecondaryIndexes']['lsi1']['CapacityUnits'] == _INDEX_ONLY_RCU, (
        f"the LocalSecondaryIndexes['lsi1'] arm must carry {_INDEX_ONLY_RCU!r} RCU, got "
        f"{bare_cc['LocalSecondaryIndexes']!r}"
    )

    # Control: naming a projected (key) attribute still needs no base-table fetch.
    projected = ddb.query(TableName=table, IndexName='lsi1', KeyConditionExpression='pk = :p',
                          ProjectionExpression='sk',
                          ExpressionAttributeValues={':p': {'S': 'P'}}, ConsistentRead=True,
                          ReturnConsumedCapacity='INDEXES')
    assert projected['Items'] == [{'sk': {'S': 'S1'}}], (
        f'a ProjectionExpression naming only a projected attribute must return exactly that '
        f'attribute, got {projected["Items"]!r}'
    )
    projected_cc = projected['ConsumedCapacity']
    assert projected_cc['CapacityUnits'] == _INDEX_ONLY_RCU, (
        f'naming a projected attribute must still bill the index-only {_INDEX_ONLY_RCU!r} RCU, '
        f'got {projected_cc["CapacityUnits"]!r} -- it must not trigger a base-table fetch'
    )
    assert projected_cc['Table']['CapacityUnits'] == 0, (
        f'naming a projected attribute must charge the Table arm nothing, got '
        f'{projected_cc["Table"]!r}'
    )

    # The behaviour under test: naming a NON-projected attribute forces a base-table fetch.
    fetched = ddb.query(TableName=table, IndexName='lsi1', KeyConditionExpression='pk = :p',
                        ProjectionExpression='payload',
                        ExpressionAttributeValues={':p': {'S': 'P'}}, ConsistentRead=True,
                        ReturnConsumedCapacity='INDEXES')
    assert fetched['Items'] == [{'payload': {'S': _PAYLOAD}}], (
        f'the non-projected attribute must be fetched from the base table and returned, got '
        f'{fetched["Items"]!r}'
    )
    fetched_cc = fetched['ConsumedCapacity']
    assert fetched_cc['Table']['CapacityUnits'] == _BASE_RCU, (
        f'the base-table fetch of a {_BASE_ITEM_BYTES!r}-byte item must bill exactly '
        f'{_BASE_RCU!r} RCU on the Table arm, got {fetched_cc["Table"]!r}'
    )
    assert fetched_cc['LocalSecondaryIndexes']['lsi1']['CapacityUnits'] == _INDEX_ONLY_RCU, (
        f"the LocalSecondaryIndexes['lsi1'] arm must still carry the unchanged index-only "
        f"{_INDEX_ONLY_RCU!r} RCU, got {fetched_cc['LocalSecondaryIndexes']!r}"
    )
    assert fetched_cc['CapacityUnits'] == _INDEX_ONLY_RCU + _BASE_RCU, (
        f'the total must be the index-only read PLUS the base item\'s 4 KB-rounded size: '
        f'{_INDEX_ONLY_RCU!r} + {_BASE_RCU!r} = {_INDEX_ONLY_RCU + _BASE_RCU!r}, got '
        f'{fetched_cc["CapacityUnits"]!r}'
    )
    assert fetched_cc['CapacityUnits'] - bare_cc['CapacityUnits'] == _BASE_RCU, (
        f'the non-projected-attribute Query must exceed the KEYS_ONLY-only read by exactly the '
        f"base item's 4 KB-rounded size, {_BASE_RCU!r} RCU, got a difference of "
        f'{fetched_cc["CapacityUnits"] - bare_cc["CapacityUnits"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
