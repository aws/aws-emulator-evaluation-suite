"""update-expression-remove."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-expression-remove"
GROUP = 'expressions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateExpression REMOVE deletes attributes from an item."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real-check', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'upd-rm'}, 'keep': {'S': 'yes'}, 'extra': {'S': 'no'}})
    ddb.update_item(TableName=table, Key={'pk': {'S': 'upd-rm'}}, UpdateExpression='REMOVE extra')
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'upd-rm'}}, ConsistentRead=True).get('Item')
    assert got is not None, "item vanished after REMOVE update"
    assert 'extra' not in got, f"REMOVE did not delete 'extra', got attributes: {sorted(got)}"
    assert got['keep'] == {'S': 'yes'}, f"unrelated attribute 'keep' was mutated by REMOVE: {got.get('keep')!r}"
    assert set(got) == {'pk', 'keep'}, f"expected exactly {{pk, keep}} to remain, got: {sorted(got)}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
