"""get-item-attributes-to-get-omits-a-missing-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-item-attributes-to-get-omits-a-missing-attribute"
GROUP = 'legacy'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """The legacy AttributesToGet naming an attribute the item does not have OMITS it rather than
    erroring -- an over-strict engine rejects the read instead."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'v': {'S': 'x'}})
    item = ddb.get_item(TableName=table, Key={'pk': {'S': 'a'}},
                        AttributesToGet=['v', 'no-such-attribute'], ConsistentRead=True)['Item']
    assert item == {'v': {'S': 'x'}}, (
        f'a missing attribute is omitted, not an error, and nothing else is added: got {item}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
