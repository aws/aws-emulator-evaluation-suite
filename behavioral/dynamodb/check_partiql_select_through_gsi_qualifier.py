"""partiql-select-through-gsi-qualifier."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-select-through-gsi-qualifier"
GROUP = 'partiql'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """PartiQL SELECT addressing a GSI as "table"."index" reads through the index and returns the
    projected item, not a table scan."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gpk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'N'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': 'gsi1',
            'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'sk': {'S': '1'}, 'gpk': {'S': 'g1'}, 'lsk': {'N': '5'}, 'extra': {'S': 'e'}})
    res = ddb.execute_statement(Statement=f'SELECT * FROM "{table}"."gsi1" WHERE gpk = \'g1\'')
    items = res.get('Items', [])
    assert len(items) == 1, f'expected exactly the one indexed item, got {len(items)}'
    assert items[0]['pk'] == {'S': 'a'}, f"expected pk=a, got {items[0].get('pk')}"
    assert items[0].get('extra') == {'S': 'e'}, 'an ALL-projection GSI must return the non-key attribute'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
