"""update-expression-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-expression-set"
GROUP = 'expressions'
SERVICES = ['dynamodb']

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateExpression SET adds/modifies attributes."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=_TAGS_KV)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'upd-set'}, 'a': {'N': '1'}})
    ddb.update_item(TableName=table, Key={'pk': {'S': 'upd-set'}}, UpdateExpression='SET a = :new, b = :b', ExpressionAttributeValues={':new': {'N': '2'}, ':b': {'S': 'added'}})
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'upd-set'}}, ConsistentRead=True).get('Item')
    assert got['a'] == {'N': '2'}, f"SET on existing attribute did not take effect: expected a={{'N': '2'}}, got {got.get('a')!r}"
    assert got['b'] == {'S': 'added'}, f"SET did not add new attribute: expected b={{'S': 'added'}}, got {got.get('b')!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
