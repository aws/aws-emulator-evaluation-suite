"""update-return-values."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-return-values"
GROUP = 'expressions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem with ReturnValues=ALL_NEW returns the full updated item, and the
    update is durably visible to an independent GetItem — the UpdateItem response
    alone is not proof the write landed."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[
            {'Key': 'sim2real:managed', 'Value': 'true'},
            {'Key': 'sim2real:prefix', 'Value': 'sim2real-behav'},
        ],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    key = {'pk': {'S': 'rv-upd'}}
    ddb.put_item(TableName=table, Item={**key, 'x': {'N': '1'}})
    resp = ddb.update_item(TableName=table, Key=key, UpdateExpression='SET x = :v', ExpressionAttributeValues={':v': {'N': '42'}}, ReturnValues='ALL_NEW')
    attrs = resp['Attributes']
    assert attrs['pk'] == {'S': 'rv-upd'}, f"UpdateItem ALL_NEW must echo the key, got {attrs}"
    assert attrs['x'] == {'N': '42'}, f"UpdateItem ALL_NEW must return the new value, got {attrs}"

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
    assert item is not None, f"expected key rv-upd to persist after the update, got {item}"
    assert item['x'] == {'N': '42'}, f"expected the persisted value to be 42 after the update, got {item}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
