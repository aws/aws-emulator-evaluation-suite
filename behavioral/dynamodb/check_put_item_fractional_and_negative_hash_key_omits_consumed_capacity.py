"""put-item-fractional-and-negative-hash-key-omits-consumed-capacity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-item-fractional-and-negative-hash-key-omits-consumed-capacity"
GROUP = 'representation'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A fractional N (3.14) and a negative N (-100) hash key each round-trip through PutItem
    and GetItem exactly; ReturnConsumedCapacity=NONE omits ConsumedCapacity on both calls.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'N'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})

    items = {
        '3.14': {'pk': {'N': '3.14'}, 'label': {'S': 'frac'}},
        '-100': {'pk': {'N': '-100'}, 'label': {'S': 'neg'}},
    }

    for key, item in items.items():
        put_resp = ddb.put_item(TableName=t, Item=item, ReturnConsumedCapacity='NONE')
        assert 'ConsumedCapacity' not in put_resp, (
            f"PutItem of pk={key!r} with ReturnConsumedCapacity=NONE must omit ConsumedCapacity, "
            f"got {put_resp.get('ConsumedCapacity')!r}"
        )

    for key, item in items.items():
        get_resp = ddb.get_item(
            TableName=t, Key={'pk': item['pk']}, ConsistentRead=True, ReturnConsumedCapacity='NONE',
        )
        assert get_resp.get('Item') == item, (
            f"GetItem for pk={key!r} must read back the exact stored item, got {get_resp.get('Item')!r}"
        )
        assert 'ConsumedCapacity' not in get_resp, (
            f"GetItem of pk={key!r} with ReturnConsumedCapacity=NONE must omit ConsumedCapacity, "
            f"got {get_resp.get('ConsumedCapacity')!r}"
        )

    # Positive control: the same two calls with ReturnConsumedCapacity=TOTAL return the table's
    # one-unit charge, so the omission above is the option's effect.
    control_item = {'pk': {'N': '42'}, 'label': {'S': 'control'}}
    put_total = ddb.put_item(TableName=t, Item=control_item, ReturnConsumedCapacity='TOTAL')
    put_cc = put_total.get('ConsumedCapacity')
    assert put_cc == {'TableName': t, 'CapacityUnits': 1.0}, (
        f"PutItem of a small item with ReturnConsumedCapacity=TOTAL must charge 1.0 unit, got {put_cc!r}"
    )
    get_total = ddb.get_item(
        TableName=t, Key={'pk': control_item['pk']}, ConsistentRead=True, ReturnConsumedCapacity='TOTAL',
    )
    get_cc = get_total.get('ConsumedCapacity')
    assert get_cc == {'TableName': t, 'CapacityUnits': 1.0}, (
        f"a strongly consistent GetItem of a small item with ReturnConsumedCapacity=TOTAL must "
        f"charge 1.0 unit, got {get_cc!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
