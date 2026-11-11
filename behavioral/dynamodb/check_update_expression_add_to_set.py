"""update-expression-add-to-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-expression-add-to-set"
GROUP = 'expressions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateExpression ADD on a String Set adds elements."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': 'update-expression-add-to-set'}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'upd-ss'}, 'tags': {'SS': ['a', 'b']}})
    ddb.update_item(TableName=table, Key={'pk': {'S': 'upd-ss'}}, UpdateExpression='ADD tags :new_tags', ExpressionAttributeValues={':new_tags': {'SS': ['b', 'c']}})
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'upd-ss'}}, ConsistentRead=True).get('Item')
    assert set(got['tags']['SS']) == {'a', 'b', 'c'}, (
        f"ADD on a String Set must union and dedup: expected {{'a', 'b', 'c'}}, got {got['tags']['SS']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
