"""update-expression-delete-from-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-expression-delete-from-set"
GROUP = 'expressions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateExpression DELETE removes elements from a String Set."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'upd-del'}, 'tags': {'SS': ['x', 'y', 'z']}})
    ddb.update_item(TableName=table, Key={'pk': {'S': 'upd-del'}}, UpdateExpression='DELETE tags :rm', ExpressionAttributeValues={':rm': {'SS': ['y']}})
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'upd-del'}}, ConsistentRead=True).get('Item')
    assert set(got['tags']['SS']) == {'x', 'z'}, (
        f"DELETE tags :rm with :rm={{'y'}} must leave the surviving members {{'x', 'z'}}, "
        f"got {got['tags']['SS']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
