"""numeric-key-is-canonicalized-on-every-path."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "numeric-key-is-canonicalized-on-every-path"
GROUP = 'representation'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Number key written as 00042 is stored canonical by PutItem, BatchWriteItem and TransactWriteItems, and GetItem,
    UpdateItem and DeleteItem reach it through a different spelling, so every write and read path canonicalizes.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-numkey-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'N'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def _get(spelling):
        return ddb.get_item(
            TableName=table, Key={'pk': {'N': spelling}}, ConsistentRead=True,
        ).get('Item')

    # --- PutItem writes canonical; four spellings of the key all reach it ---
    ddb.put_item(TableName=table, Item={'pk': {'N': '42'}, 'via': {'S': 'put'}})
    for spelling in ('42', '00042', '42.0', '4.2e1'):
        found = _get(spelling)
        assert found == {'pk': {'N': '42'}, 'via': {'S': 'put'}}, (
            f'GetItem with the key spelled {spelling!r} must resolve to the item stored under the '
            f'canonical key 42, got {found!r}'
        )

    # --- BatchWriteItem indexes a non-canonical key canonically ---
    ddb.batch_write_item(RequestItems={table: [
        {'PutRequest': {'Item': {'pk': {'N': '00043'}, 'via': {'S': 'batch'}}}},
    ]})
    batched = _get('43')
    assert batched == {'pk': {'N': '43'}, 'via': {'S': 'batch'}}, (
        f'an item written by BatchWriteItem with the key spelled 00043 must be reachable as 43 and '
        f'store the canonical key, got {batched!r}'
    )

    # --- TransactWriteItems does the same ---
    ddb.transact_write_items(TransactItems=[
        {'Put': {'TableName': table, 'Item': {'pk': {'N': '0044.00'}, 'via': {'S': 'transact'}}}},
    ])
    transacted = _get('44')
    assert transacted == {'pk': {'N': '44'}, 'via': {'S': 'transact'}}, (
        f'an item written by TransactWriteItems with the key spelled 0044.00 must be reachable as '
        f'44 and store the canonical key, got {transacted!r}'
    )

    # --- UpdateItem addressed by a non-canonical key reaches the same item ---
    ddb.update_item(
        TableName=table,
        Key={'pk': {'N': '004.2e1'}},
        UpdateExpression='SET via = :v',
        ExpressionAttributeValues={':v': {'S': 'updated'}},
    )
    updated = _get('42')
    assert updated == {'pk': {'N': '42'}, 'via': {'S': 'updated'}}, (
        f'UpdateItem keyed by 004.2e1 must update the item stored under 42 rather than creating a '
        f'second one, got {updated!r}'
    )

    # --- DeleteItem resolves its key too, and returns the canonical form ---
    removed = ddb.delete_item(
        TableName=table, Key={'pk': {'N': '0042.0'}}, ReturnValues='ALL_OLD',
    )
    assert removed.get('Attributes') == {'pk': {'N': '42'}, 'via': {'S': 'updated'}}, (
        f'DeleteItem keyed by 0042.0 must delete the item stored under 42 and echo the canonical '
        f'key, got {removed.get("Attributes")!r}'
    )
    assert _get('42') is None, (
        f'the item must really be gone after the non-canonical delete, found {_get("42")!r}'
    )

    # --- the other two paths' items are untouched by that delete ---
    assert _get('43') is not None and _get('44') is not None, (
        f'deleting 42 must not disturb the other keys: 43 -> {_get("43")!r}, 44 -> {_get("44")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
