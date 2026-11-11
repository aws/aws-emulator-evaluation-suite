"""expression-attribute-names."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "expression-attribute-names"
GROUP = 'expressions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExpressionAttributeNames allows using reserved words as attribute names, and
    GetItem's ProjectionExpression actually restricts the returned attributes to the
    aliased set rather than returning the whole item."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': 'expression-attribute-names'}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'ean'}, 'status': {'S': 'active'}, 'name': {'S': 'test'}, 'secret': {'S': 'unrequested'}})
    resp = ddb.get_item(TableName=table, Key={'pk': {'S': 'ean'}}, ProjectionExpression='#s, #n', ExpressionAttributeNames={'#s': 'status', '#n': 'name'}, ConsistentRead=True)
    got = resp['Item']
    assert got.get('status') == {'S': 'active'}, f"expected status=active via #s alias, got {got.get('status')!r}"
    assert got.get('name') == {'S': 'test'}, f"expected name=test via #n alias, got {got.get('name')!r}"
    assert 'secret' not in got, f"ProjectionExpression '#s, #n' must exclude unaliased attributes, got keys {sorted(got)}"
    assert set(got) == {'status', 'name'}, f"expected exactly the aliased attributes, got keys {sorted(got)}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
