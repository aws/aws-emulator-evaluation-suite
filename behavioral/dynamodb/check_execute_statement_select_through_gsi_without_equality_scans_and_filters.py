"""execute-statement-select-through-gsi-without-equality-scans-and-filters."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "execute-statement-select-through-gsi-without-equality-scans-and-filters"
GROUP = 'partiql'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL SELECT on a GSI with an index-key equality returns both indexed items; one without
    it scans and filters to the single matching item, not a base-table item outside the sparse GSI.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlgsiscan-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'status', 'AttributeType': 'S'},
            {'AttributeName': 'createdAt', 'AttributeType': 'S'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': 'status-index',
            'KeySchema': [{'AttributeName': 'status', 'KeyType': 'HASH'}, {'AttributeName': 'createdAt', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    deadline = time.time() + 300
    gsi_status = None
    while time.time() < deadline:
        described = ddb.describe_table(TableName=table)['Table']
        gsi_status = {i['IndexName']: i['IndexStatus'] for i in described.get('GlobalSecondaryIndexes', [])}
        if gsi_status.get('status-index') == 'ACTIVE':
            break
        time.sleep(2)
    assert gsi_status.get('status-index') == 'ACTIVE', f'status-index never became ACTIVE: {gsi_status!r}'

    ddb.put_item(TableName=table, Item={'pk': {'S': 'P1'}, 'sk': {'S': 's1'}, 'status': {'S': 'active'}, 'createdAt': {'S': '2024-01-01'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'P1'}, 'sk': {'S': 's2'}, 'status': {'S': 'active'}, 'createdAt': {'S': '2024-01-02'}})
    # In the base table only: it lacks the index keys, so the sparse GSI never holds it.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'P2'}, 'sk': {'S': 's2'}})

    # Positive control: an equality predicate on the index partition key routes through the
    # index and sees BOTH items, establishing that the index genuinely holds more than the one
    # item the filtered statement below must narrow down to.
    deadline = time.time() + 120
    all_items = []
    while time.time() < deadline:
        all_items = ddb.execute_statement(
            Statement=f'SELECT * FROM "{table}"."status-index" WHERE status = \'active\'',
        ).get('Items', [])
        if len(all_items) == 2:
            break
        time.sleep(1)
    assert sorted(i['sk']['S'] for i in all_items) == ['s1', 's2'], (
        f'the index must hold both items before the filtered statement below can prove it '
        f'scanned rather than returning everything by coincidence: {all_items!r}'
    )

    # Break the equality: the same index, with a WHERE clause on an attribute that is not part
    # of the index's key schema. Real AWS scans the index and applies this as a filter,
    # returning only the matching item.
    filtered = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}"."status-index" WHERE sk = \'s2\'',
    )
    filtered_items = filtered.get('Items', [])
    assert len(filtered_items) == 1, (
        f'a non-key filter against the GSI must narrow the 2-item index to the 1 matching sk, '
        f'got {len(filtered_items)} items: {filtered_items!r}'
    )
    assert filtered_items[0]['sk'] == {'S': 's2'}, (
        f"expected the surviving item's sk to be 's2', got {filtered_items[0].get('sk')!r}"
    )
    assert filtered_items[0]['pk'] == {'S': 'P1'}, (
        f"the index scan must not return the base-table-only item, got {filtered_items[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
