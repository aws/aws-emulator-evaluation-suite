"""legacy-attribute-updates-dotted-name-is-literal."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "legacy-attribute-updates-dotted-name-is-literal"
GROUP = 'item_crud'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy AttributeUpdates keys an attribute by its literal name: a dot in that
    name creates one top-level attribute rather than reaching inside a nested map.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-behav', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=t, Item={'pk': {'S': 'movie'}, 'info': {'M': {'plot': {'S': 'original'}}}})
    ddb.update_item(
        TableName=t, Key={'pk': {'S': 'movie'}},
        AttributeUpdates={'info.plot': {'Value': {'S': 'rewritten'}, 'Action': 'PUT'}},
    )
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'movie'}}, ConsistentRead=True).get('Item')
    assert got.get('info.plot') == {'S': 'rewritten'}, (
        f"expected a literal top-level attribute named 'info.plot', got {got!r}"
    )
    assert got.get('info') == {'M': {'plot': {'S': 'original'}}}, (
        f"AttributeUpdates keyed by 'info.plot' must not touch the nested info.plot path, "
        f"got {got.get('info')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
