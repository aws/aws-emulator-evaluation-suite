"""projection-expression."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "projection-expression"
GROUP = 'expressions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ProjectionExpression limits attributes returned by GetItem."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'proj'}, 'a': {'S': '1'}, 'b': {'S': '2'}, 'c': {'S': '3'}})
    resp = ddb.get_item(TableName=table, Key={'pk': {'S': 'proj'}}, ProjectionExpression='pk, a', ConsistentRead=True)
    got = resp['Item']
    assert 'a' in got, f'expected projected attribute a present, got keys {sorted(got)}'
    assert 'pk' in got, f'expected key attribute pk present, got keys {sorted(got)}'
    assert 'b' not in got, f'expected non-projected attribute b absent, got keys {sorted(got)}'
    assert 'c' not in got, f'expected non-projected attribute c absent, got keys {sorted(got)}'

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
