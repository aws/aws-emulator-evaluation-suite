"""delete-item."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-item"
GROUP = 'item_crud'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteItem removes the item: an independent read confirms it is gone, and a
    conditional mutation that requires the item to still exist now fails."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': 'true'}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {'pk': {'S': 'to-delete'}}
    ddb.put_item(TableName=table, Item={**key, 'x': {'S': 'y'}})

    before = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
    assert before is not None, f"expected item present before delete, got {before!r}"
    assert before.get('x') == {'S': 'y'}, f"expected x=y before delete, got {before!r}"

    ddb.delete_item(TableName=table, Key=key)

    after = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
    assert after is None, f"expected item absent after delete, got {after!r}"

    try:
        ddb.delete_item(TableName=table, Key=key, ConditionExpression='attribute_exists(pk)')
        raise AssertionError("expected ConditionalCheckFailedException deleting an already-deleted key")
    except ddb.exceptions.ConditionalCheckFailedException as exc:
        message = exc.response['Error'].get('Message')
        assert message == 'The conditional request failed', message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
