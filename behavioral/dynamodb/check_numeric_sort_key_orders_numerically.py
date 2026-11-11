"""numeric-sort-key-orders-numerically."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "numeric-sort-key-orders-numerically"
GROUP = 'query'
SERVICES = ['dynamodb']

# Chosen so the NUMERIC order and the LEXICOGRAPHIC order of the same strings differ:
#   numeric:       -20, -3, 0, 2, 9.5, 10, 100, 1000
#   lexicographic: '-20', '-3', '0', '10', '100', '1000', '2', '9.5'
# Every literal is already in DynamoDB canonical form (no leading/trailing zeros), so the
# stored representation round-trips byte-identically and the assertions can compare strings.
_SK_NUMERIC_ORDER = ['-20', '-3', '0', '2', '9.5', '10', '100', '1000']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An N-typed sort key collates numerically, not as strings: Query order both ways, BETWEEN, >
    and < follow numeric order with negative and fractional keys, and GetItem resolves 9.5 exactly.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'N'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Insert in an order that is neither numeric nor lexicographic, so a store that returns
    # insertion order also fails.
    for sk in ['100', '-3', '1000', '9.5', '0', '10', '-20', '2']:
        ddb.put_item(TableName=t, Item={'pk': {'S': 'n'}, 'sk': {'N': sk}})

    base = {
        'TableName': t,
        'KeyConditionExpression': 'pk = :p',
        'ExpressionAttributeValues': {':p': {'S': 'n'}},
        'ConsistentRead': True,
    }

    asc = [it['sk']['N'] for it in ddb.query(**base)['Items']]
    assert asc == _SK_NUMERIC_ORDER, (
        f'N sort key must ascend numerically {_SK_NUMERIC_ORDER}, got {asc} '
        f'(lexicographic order would be {sorted(_SK_NUMERIC_ORDER)})'
    )

    desc = [it['sk']['N'] for it in ddb.query(**base, ScanIndexForward=False)['Items']]
    assert desc == list(reversed(_SK_NUMERIC_ORDER)), (
        f'ScanIndexForward=False must reverse the NUMERIC order, got {desc}'
    )

    between = ddb.query(
        TableName=t,
        KeyConditionExpression='pk = :p AND sk BETWEEN :lo AND :hi',
        ExpressionAttributeValues={':p': {'S': 'n'}, ':lo': {'N': '0'}, ':hi': {'N': '100'}},
        ConsistentRead=True,
    )
    between_sks = [it['sk']['N'] for it in between['Items']]
    assert between_sks == ['0', '2', '9.5', '10', '100'], (
        f'BETWEEN 0 AND 100 on an N sort key must select the numeric interval (inclusive of '
        f'both bounds), got {between_sks}'
    )

    greater = ddb.query(
        TableName=t,
        KeyConditionExpression='pk = :p AND sk > :v',
        ExpressionAttributeValues={':p': {'S': 'n'}, ':v': {'N': '9'}},
        ConsistentRead=True,
    )
    greater_sks = [it['sk']['N'] for it in greater['Items']]
    assert greater_sks == ['9.5', '10', '100', '1000'], (
        f'sk > 9 on an N sort key must select every numerically larger key, got {greater_sks} '
        f'(a string comparison would yield only 9.5)'
    )

    negatives = ddb.query(
        TableName=t,
        KeyConditionExpression='pk = :p AND sk < :v',
        ExpressionAttributeValues={':p': {'S': 'n'}, ':v': {'N': '0'}},
        ConsistentRead=True,
    )
    negative_sks = [it['sk']['N'] for it in negatives['Items']]
    assert negative_sks == ['-20', '-3'], (
        f'negative N sort keys must ascend -20 then -3, got {negative_sks} '
        f'(a string comparison would yield -20 after -3)'
    )

    # A single point read on an N key must resolve through the same collation.
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'n'}, 'sk': {'N': '9.5'}}, ConsistentRead=True)
    assert got.get('Item', {}).get('sk') == {'N': '9.5'}, (
        f'GetItem on an N sort key must resolve the fractional key exactly, got {got.get("Item")}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
