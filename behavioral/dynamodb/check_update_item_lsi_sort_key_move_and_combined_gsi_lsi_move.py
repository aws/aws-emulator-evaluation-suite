"""update-item-lsi-sort-key-move-and-combined-gsi-lsi-move."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-item-lsi-sort-key-move-and-combined-gsi-lsi-move"
GROUP = 'lsi'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem that changes an LSI sort-key attribute moves the LSI entry: a strongly
    consistent Query on the old value returns nothing, the new value returns the item. A single
    UpdateItem that changes a GSI key and an LSI key together moves both index entries.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-lsimove-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'sk', 'AttributeType': 'S'},
                              {'AttributeName': 'lsisk', 'AttributeType': 'S'},
                              {'AttributeName': 'gsi1pk', 'AttributeType': 'S'}],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                         {'AttributeName': 'lsisk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
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
    gsi_status = None
    while time.time() < deadline:
        described = ddb.describe_table(TableName=table)['Table']
        gsi_status = {i['IndexName']: i['IndexStatus']
                     for i in described.get('GlobalSecondaryIndexes', [])}
        if gsi_status.get('gsi1') == 'ACTIVE':
            break
        time.sleep(2)
    assert gsi_status.get('gsi1') == 'ACTIVE', (
        f'gsi1 never became ACTIVE within 300s: {gsi_status!r}'
    )

    def _lsi_query(pk, lsisk_value):
        return ddb.query(TableName=table, IndexName='lsi1', ConsistentRead=True,
                         KeyConditionExpression='pk = :p AND lsisk = :v',
                         ExpressionAttributeValues={':p': {'S': pk}, ':v': {'S': lsisk_value}})

    def _gsi_query(gsi1pk_value):
        return ddb.query(TableName=table, IndexName='gsi1',
                         KeyConditionExpression='gsi1pk = :g',
                         ExpressionAttributeValues={':g': {'S': gsi1pk_value}})

    # Part 1: an UpdateItem that changes only the LSI sort key moves only that entry.
    pk1 = 'ORDER#1'
    ddb.put_item(TableName=table, Item={'pk': {'S': pk1}, 'sk': {'S': 'S1'},
                                        'lsisk': {'S': 'A'}, 'payload': {'S': 'p1'}})

    before = _lsi_query(pk1, 'A')
    assert [i['pk']['S'] for i in before['Items']] == [pk1], (
        f'the item never appeared under the original LSI sort key lsisk=A: {before["Items"]!r}'
    )

    ddb.update_item(TableName=table, Key={'pk': {'S': pk1}, 'sk': {'S': 'S1'}},
                    UpdateExpression='SET lsisk = :new',
                    ExpressionAttributeValues={':new': {'S': 'B'}})

    old_after = _lsi_query(pk1, 'A')
    assert old_after['Items'] == [], (
        f'the stale LSI entry under lsisk=A survived the sort-key update: {old_after["Items"]!r}'
    )
    new_after = _lsi_query(pk1, 'B')
    assert [i['pk']['S'] for i in new_after['Items']] == [pk1], (
        f'the item never appeared under the new LSI sort key lsisk=B: {new_after["Items"]!r}'
    )

    base1 = ddb.get_item(TableName=table, Key={'pk': {'S': pk1}, 'sk': {'S': 'S1'}},
                         ConsistentRead=True)
    assert base1['Item']['lsisk']['S'] == 'B', f'the base item was not updated: {base1["Item"]!r}'
    assert base1['Item']['payload']['S'] == 'p1', (
        f'the sort-key update clobbered a non-key attribute: {base1["Item"]!r}'
    )

    # Part 2: one UpdateItem that changes a GSI key and the LSI sort key together moves both.
    pk2 = 'ORDER#2'
    ddb.put_item(TableName=table, Item={'pk': {'S': pk2}, 'sk': {'S': 'S2'},
                                        'lsisk': {'S': 'C'}, 'gsi1pk': {'S': 'X'},
                                        'payload': {'S': 'p2'}})

    lsi_before2 = _lsi_query(pk2, 'C')
    assert [i['pk']['S'] for i in lsi_before2['Items']] == [pk2], (
        f'the second item never appeared under its original LSI sort key lsisk=C: '
        f'{lsi_before2["Items"]!r}'
    )
    gsi_deadline = time.time() + 120
    gsi_before2 = _gsi_query('X')
    while not gsi_before2['Items'] and time.time() < gsi_deadline:
        time.sleep(2)
        gsi_before2 = _gsi_query('X')
    assert [i['pk']['S'] for i in gsi_before2['Items']] == [pk2], (
        f'the second item never appeared under its original GSI key gsi1pk=X: '
        f'{gsi_before2["Items"]!r}'
    )

    ddb.update_item(TableName=table, Key={'pk': {'S': pk2}, 'sk': {'S': 'S2'}},
                    UpdateExpression='SET lsisk = :newlsi, gsi1pk = :newgsi',
                    ExpressionAttributeValues={':newlsi': {'S': 'D'}, ':newgsi': {'S': 'Y'}})

    lsi_old_after2 = _lsi_query(pk2, 'C')
    assert lsi_old_after2['Items'] == [], (
        f'the stale LSI entry under lsisk=C survived the combined update: '
        f'{lsi_old_after2["Items"]!r}'
    )
    lsi_new_after2 = _lsi_query(pk2, 'D')
    assert [i['pk']['S'] for i in lsi_new_after2['Items']] == [pk2], (
        f'the item never appeared under the new LSI sort key lsisk=D: {lsi_new_after2["Items"]!r}'
    )

    gsi_move_deadline = time.time() + 120
    gsi_y_items, gsi_x_items = [], [None]
    while time.time() < gsi_move_deadline:
        gsi_y_items = _gsi_query('Y')['Items']
        gsi_x_items = _gsi_query('X')['Items']
        if gsi_y_items and not gsi_x_items:
            break
        time.sleep(2)
    assert [i['pk']['S'] for i in gsi_y_items] == [pk2], (
        f'the item never appeared under the new GSI key gsi1pk=Y within 120s: {gsi_y_items!r}'
    )
    assert gsi_x_items == [], (
        f'the stale GSI entry under gsi1pk=X survived the combined update: {gsi_x_items!r}'
    )

    base2 = ddb.get_item(TableName=table, Key={'pk': {'S': pk2}, 'sk': {'S': 'S2'}},
                         ConsistentRead=True)
    assert base2['Item']['lsisk']['S'] == 'D', (
        f'the base item LSI key was not updated: {base2["Item"]!r}'
    )
    assert base2['Item']['gsi1pk']['S'] == 'Y', (
        f'the base item GSI key was not updated: {base2["Item"]!r}'
    )
    assert base2['Item']['payload']['S'] == 'p2', (
        f'the combined key update clobbered a non-key attribute: {base2["Item"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
