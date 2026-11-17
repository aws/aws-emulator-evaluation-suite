"""binary-sort-key-greater-than-excludes-pivot."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "binary-sort-key-greater-than-excludes-pivot"
GROUP = 'ordering'
SERVICES = ['dynamodb']

# Four one-byte sort keys spanning the signed/unsigned boundary.
_UNSIGNED_ORDER = [b'\x01', b'\x7f', b'\x80', b'\xff']
_PIVOT = b'\x7f'
_ABOVE_PIVOT = [b'\x80', b'\xff']
_BELOW_ALL = b'\x00'
_PREFIX = b'\x80'
_EXTENDED = b'\x80\x00'


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A strict '>' key condition on a Binary sort key compares bytes as unsigned values,
    excludes an item equal to the pivot, and a key that is a prefix of another is strictly
    below its own extension."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-binsortgt-')
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'B'},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def _query(partition, pivot, **kwargs):
        resp = ddb.query(
            TableName=table,
            KeyConditionExpression='pk = :p AND sk > :piv',
            ExpressionAttributeValues={':p': {'S': partition}, ':piv': {'B': pivot}},
            ConsistentRead=True,
            **kwargs,
        )
        return [item['sk']['B'] for item in resp['Items']]

    # Written high-to-low so insertion order cannot be mistaken for the query's order.
    for sk in reversed(_UNSIGNED_ORDER):
        ddb.put_item(TableName=table, Item={'pk': {'S': 'SPAN'}, 'sk': {'B': sk}})

    above = _query('SPAN', _PIVOT)
    assert above == _ABOVE_PIVOT, (
        f"sk > {_PIVOT.hex()!r} must exclude the pivot itself and everything below it: expected "
        f"{[b.hex() for b in _ABOVE_PIVOT]!r}, got {[b.hex() for b in above]!r}"
    )

    descending = _query('SPAN', _PIVOT, ScanIndexForward=False)
    assert descending == list(reversed(_ABOVE_PIVOT)), (
        f"ScanIndexForward=False on the same '>' condition must return exactly the reverse: "
        f"expected {[b.hex() for b in reversed(_ABOVE_PIVOT)]!r}, got "
        f"{[b.hex() for b in descending]!r}"
    )

    # Positive control: a pivot below every stored key must admit all four, in ascending order,
    # proving the operator is applied rather than silently ignored.
    all_above = _query('SPAN', _BELOW_ALL)
    assert all_above == _UNSIGNED_ORDER, (
        f"sk > {_BELOW_ALL.hex()!r} must admit every stored key in ascending unsigned-byte order: "
        f"expected {[b.hex() for b in _UNSIGNED_ORDER]!r}, got {[b.hex() for b in all_above]!r}"
    )

    # --- a prefix is strictly below its own extension under '>' too ---
    for sk in (_EXTENDED, _PREFIX):
        ddb.put_item(TableName=table, Item={'pk': {'S': 'PREFIX'}, 'sk': {'B': sk}})
    extension_only = _query('PREFIX', _PREFIX)
    assert extension_only == [_EXTENDED], (
        f"sk > {_PREFIX.hex()!r} must exclude the prefix itself and admit only its extension: "
        f"expected {[_EXTENDED.hex()]!r}, got {[b.hex() for b in extension_only]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
