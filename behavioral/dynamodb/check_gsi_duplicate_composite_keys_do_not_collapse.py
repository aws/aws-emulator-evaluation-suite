"""gsi-duplicate-composite-keys-do-not-collapse."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "gsi-duplicate-composite-keys-do-not-collapse"
GROUP = 'gsi'
SERVICES = ['dynamodb']

_ROWS = 3
_INDEX = 'shared-key-index'
_CONVERGE_S = 90.0
_INTERVAL_S = 1.0


def _poll_index(ddb, table, gsi_pk, gsi_sk, expected, *, description):
    """A GSI is eventually consistent, so wait for it to reach the expected row count rather than
    reading once. Returns the converged response and fails with what it last saw."""
    deadline = time.monotonic() + _CONVERGE_S
    last = None
    while time.monotonic() < deadline:
        last = ddb.query(
            TableName=table,
            IndexName=_INDEX,
            KeyConditionExpression='gsi_pk = :p AND gsi_sk = :s',
            ExpressionAttributeValues={':p': {'S': gsi_pk}, ':s': {'S': gsi_sk}},
        )
        if last['Count'] == expected:
            return last
        time.sleep(_INTERVAL_S)
    raise AssertionError(
        f'{description}: the index did not reach {expected!r} rows within {_CONVERGE_S}s. Last '
        f'response had Count={last["Count"]!r}: {last["Items"]!r}'
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Items sharing one GSI (hash, range) pair all stay addressable through the index: a Query returns every one,
    deleting one leaves the others, and moving one item's index key empties only its old slot.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-gsidup-')
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gsi_pk', 'AttributeType': 'S'},
            {'AttributeName': 'gsi_sk', 'AttributeType': 'S'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': _INDEX,
            'KeySchema': [
                {'AttributeName': 'gsi_pk', 'KeyType': 'HASH'},
                {'AttributeName': 'gsi_sk', 'KeyType': 'RANGE'},
            ],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for i in range(_ROWS):
        ddb.put_item(TableName=table, Item={
            'pk': {'S': f'base-{i}'},
            'sk': {'S': f'sort-{i}'},
            'gsi_pk': {'S': 'SHARED'},
            'gsi_sk': {'S': 'SAME'},
            'body': {'S': f'payload-{i}'},
        })

    scanned = ddb.scan(TableName=table, ConsistentRead=True)
    assert scanned['Count'] == _ROWS, (
        f'the base table must hold all {_ROWS!r} items -- they have distinct primary keys -- got '
        f'{scanned["Count"]!r}: {scanned["Items"]!r}'
    )

    # --- all rows sharing the index key are present ---
    indexed = _poll_index(ddb, table, 'SHARED', 'SAME', _ROWS, description='initial backfill')
    bodies = sorted(item['body']['S'] for item in indexed['Items'])
    assert bodies == [f'payload-{i}' for i in range(_ROWS)], (
        f'a Query on the shared index key must return every base item that carries it, not just '
        f'the last one written: expected {[f"payload-{i}" for i in range(_ROWS)]!r}, got {bodies!r}'
    )

    # --- deleting one leaves the others in the slot ---
    ddb.delete_item(TableName=table, Key={'pk': {'S': 'base-1'}, 'sk': {'S': 'sort-1'}})
    after_delete = _poll_index(
        ddb, table, 'SHARED', 'SAME', _ROWS - 1, description='after deleting one row',
    )
    survivors = sorted(item['pk']['S'] for item in after_delete['Items'])
    assert survivors == ['base-0', 'base-2'], (
        f'deleting one item that shares the index key must remove only that row: expected '
        f'["base-0", "base-2"] still indexed, got {survivors!r}'
    )

    # --- moving one item's index key empties only its old slot ---
    ddb.update_item(
        TableName=table,
        Key={'pk': {'S': 'base-0'}, 'sk': {'S': 'sort-0'}},
        UpdateExpression='SET gsi_sk = :new',
        ExpressionAttributeValues={':new': {'S': 'MOVED'}},
    )
    old_slot = _poll_index(ddb, table, 'SHARED', 'SAME', 1, description='old slot after a move')
    assert old_slot['Items'][0]['pk'] == {'S': 'base-2'}, (
        f'the item that did not move must still be at the shared key, got '
        f'{old_slot["Items"]!r}'
    )
    new_slot = _poll_index(ddb, table, 'SHARED', 'MOVED', 1, description='new slot after a move')
    assert new_slot['Items'][0]['pk'] == {'S': 'base-0'}, (
        f'the moved item must appear under its new index key, got {new_slot["Items"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
