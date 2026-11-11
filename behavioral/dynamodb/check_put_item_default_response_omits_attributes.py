"""put-item-default-response-omits-attributes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-item-default-response-omits-attributes"
GROUP = 'item_crud'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """With no ReturnValues and no ReturnConsumedCapacity, an overwriting PutItem answers with NO
    Attributes and no capacity -- the defaults are NONE, so a chatty response is a divergence."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'v': {'N': '1'}})
    res = ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'v': {'N': '2'}})
    keys = sorted(k for k in res if k != 'ResponseMetadata')
    assert 'Attributes' not in keys, (
        f'ReturnValues defaults to NONE, so an overwrite returns no Attributes, got {keys}'
    )
    assert 'ConsumedCapacity' not in keys, (
        f'ReturnConsumedCapacity defaults to NONE, so no capacity is reported, got {keys}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
