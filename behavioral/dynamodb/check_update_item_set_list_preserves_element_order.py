"""update-item-set-list-preserves-element-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-item-set-list-preserves-element-order"
GROUP = 'expressions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A SET writing a list preserves element order on read-back, so index 0 stays index 0. An engine
    storing the list as an unordered collection fails."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'lst'}})
    res = ddb.update_item(TableName=table, Key={'pk': {'S': 'lst'}}, UpdateExpression='SET l = :l',
                          ExpressionAttributeValues={':l': {'L': [{'N': '3'}, {'N': '1'}, {'N': '2'}]}},
                          ReturnValues='ALL_NEW')
    assert res['Attributes']['l'] == {'L': [{'N': '3'}, {'N': '1'}, {'N': '2'}]}, (
        f"the list must come back in the order written, got {res['Attributes']['l']}"
    )
    read = ddb.get_item(TableName=table, Key={'pk': {'S': 'lst'}}, ConsistentRead=True)['Item']
    assert read['l'] == {'L': [{'N': '3'}, {'N': '1'}, {'N': '2'}]}, (
        f"order must survive the round trip to storage, got {read['l']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
