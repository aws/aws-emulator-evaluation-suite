"""consumed-capacity-rounds-reads-to-4kb-boundaries."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "consumed-capacity-rounds-reads-to-4kb-boundaries"
GROUP = 'capacity'
SERVICES = ['dynamodb']

_KB = 1024
# A strongly consistent read is billed one unit per 4KB block, rounded UP. The payload sizes below
# sit well inside their blocks so the few bytes of attribute names and key cannot move either one
# across a boundary: ~1KB lands in the first block, ~3KB in the first, ~5KB in the second.
_TINY_BYTES = 1 * _KB
_UNDER_ONE_BLOCK_BYTES = 3 * _KB
_INTO_SECOND_BLOCK_BYTES = 5 * _KB


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Read capacity is the item size rounded UP to a 4KB block: 1KB and 3KB items cost 1.0 strongly
    consistent, 5KB costs 2.0, and an eventually consistent read costs exactly half (after
    rounding).
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-rcu-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    sizes = {
        'tiny': _TINY_BYTES,
        'under': _UNDER_ONE_BLOCK_BYTES,
        'over': _INTO_SECOND_BLOCK_BYTES,
    }
    for name, size in sizes.items():
        ddb.put_item(TableName=table, Item={'pk': {'S': name}, 'v': {'S': 'x' * size}})

    def _units(name, *, consistent):
        resp = ddb.get_item(
            TableName=table,
            Key={'pk': {'S': name}},
            ConsistentRead=consistent,
            ReturnConsumedCapacity='TOTAL',
        )
        assert 'Item' in resp, f'{name!r} must exist before its capacity can be read'
        return resp['ConsumedCapacity']['CapacityUnits']

    expected_strong = {'tiny': 1.0, 'under': 1.0, 'over': 2.0}
    for name, expected in expected_strong.items():
        actual = _units(name, consistent=True)
        assert actual == expected, (
            f'a strongly consistent GetItem on the ~{sizes[name] // _KB!r}KB item must cost '
            f'{expected!r} capacity units -- the item size rounded up to a 4KB block -- got '
            f'{actual!r}'
        )

    for name, strong in expected_strong.items():
        actual = _units(name, consistent=False)
        assert actual == strong / 2, (
            f'an eventually consistent read costs exactly half its strongly consistent cost, so '
            f'the ~{sizes[name] // _KB!r}KB item must cost {strong / 2!r}, got {actual!r}. The '
            f'discount applies AFTER rounding'
        )

    # The two items inside one block cost the same, which no byte-proportional figure can produce.
    assert _units('tiny', consistent=True) == _units('under', consistent=True), (
        f'a ~1KB item and a ~3KB item share a block and must cost the same: got '
        f'{_units("tiny", consistent=True)!r} and {_units("under", consistent=True)!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
