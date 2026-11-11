"""put-item-binary-set-zero-length-member-round-trips."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = 'put-item-binary-set-zero-length-member-round-trips'
GROUP = 'representation'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:representation", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem accepts a Binary Set holding a zero-length member on its own, and alongside a
    non-empty member, and GetItem reads the empty member back intact."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-bszero-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={'pk': {'S': 'solo'}, 's': {'BS': [b'']}})
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'solo'}}, ConsistentRead=True).get('Item', {})
    members = got.get('s', {}).get('BS')
    assert members == [b''], (
        f'a BS holding only a zero-length member must round-trip as [b""], got {members!r}'
    )

    ddb.put_item(TableName=t, Item={'pk': {'S': 'mixed'}, 's': {'BS': [b'', b'\x01']}})
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'mixed'}}, ConsistentRead=True).get('Item', {})
    members = got.get('s', {}).get('BS')
    assert sorted(members or []) == sorted([b'', b'\x01']), (
        f'a BS mixing a zero-length member with b"\\x01" must keep both, got {members!r}'
    )

    scanned = ddb.scan(TableName=t, ConsistentRead=True, Select='COUNT')
    assert scanned['Count'] == 2, (
        f'only the two items just written may exist, got {scanned["Count"]!r} items'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
