"""gsi-key-attribute-update-moves-the-index-entry."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "gsi-key-attribute-update-moves-the-index-entry"
GROUP = 'gsi'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Updating an item's GSI partition-key attribute from A to B moves the index entry: a GSI Query on B returns the
    item, a Query on A returns none, and the base table holds one item with the new value.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-gsimove-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'sk', 'AttributeType': 'S'},
                              {'AttributeName': 'gsi1pk', 'AttributeType': 'S'}],
        GlobalSecondaryIndexes=[{
            'IndexName': 'gsi1',
            'KeySchema': [{'AttributeName': 'gsi1pk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    deadline = time.time() + 300
    index_status = None
    while time.time() < deadline:
        described = ddb.describe_table(TableName=table)['Table']
        index_status = {i['IndexName']: i['IndexStatus']
                        for i in described.get('GlobalSecondaryIndexes', [])}
        if index_status.get('gsi1') == 'ACTIVE':
            break
        time.sleep(2)
    assert index_status.get('gsi1') == 'ACTIVE', (
        f'gsi1 never became ACTIVE within 300s: {index_status!r}'
    )

    pk = 'ORDER#1'
    ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'sk': {'S': 'S1'},
                                        'gsi1pk': {'S': 'A'}, 'payload': {'S': 'p'}})

    def _query(value):
        return ddb.query(TableName=table, IndexName='gsi1',
                         KeyConditionExpression='gsi1pk = :g',
                         ExpressionAttributeValues={':g': {'S': value}})

    # The index must first become populated under the ORIGINAL key value, otherwise the
    # disappearance asserted below would be indistinguishable from an index that never indexed.
    deadline = time.time() + 120
    a_before = _query('A')
    while not a_before['Items'] and time.time() < deadline:
        time.sleep(1)
        a_before = _query('A')
    assert [i['pk']['S'] for i in a_before['Items']] == [pk], (
        f'the item never appeared under the original index key gsi1pk=A: {a_before["Items"]!r}'
    )
    a_count_scanned = a_before['ScannedCount']

    ddb.update_item(TableName=table, Key={'pk': {'S': pk}, 'sk': {'S': 'S1'}},
                    UpdateExpression='SET gsi1pk = :new',
                    ExpressionAttributeValues={':new': {'S': 'B'}})

    # The move is two effects, and an emulator can produce either one alone: the new entry
    # appearing, and the old one going away. Poll until BOTH hold.
    deadline = time.time() + 120
    b_items, a_items = [], [None]
    while time.time() < deadline:
        b_items = _query('B')['Items']
        a_items = _query('A')['Items']
        if b_items and not a_items:
            break
        time.sleep(2)

    assert [i['pk']['S'] for i in b_items] == [pk], (
        f'the item never appeared under the new index key gsi1pk=B within 120s: {b_items!r}'
    )
    assert a_items == [], (
        f'the stale index entry under gsi1pk=A survived the key update: {a_items!r}'
    )
    assert a_count_scanned >= 1, (
        f'the query against the old key never actually ran against a populated index, so its '
        f'emptiness above proves nothing: ScannedCount was {a_count_scanned!r}'
    )

    base = ddb.get_item(TableName=table, Key={'pk': {'S': pk}, 'sk': {'S': 'S1'}},
                        ConsistentRead=True)
    assert base['Item']['gsi1pk']['S'] == 'B', (
        f'the base item was not updated: {base["Item"]!r}'
    )
    assert base['Item']['payload']['S'] == 'p', (
        f'the key update clobbered a non-key attribute: {base["Item"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
