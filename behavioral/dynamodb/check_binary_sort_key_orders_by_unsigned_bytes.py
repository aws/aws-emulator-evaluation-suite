"""binary-sort-key-orders-by-unsigned-bytes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "binary-sort-key-orders-by-unsigned-bytes"
GROUP = 'ordering'
SERVICES = ['dynamodb']

# Four one-byte sort keys spanning the signed boundary. Compared as UNSIGNED bytes this is the
# ascending order; compared as signed bytes the last two are negative and sort BELOW the first two,
# which inverts the top half of the range.
_UNSIGNED_ORDER = [b'\x01', b'\x7f', b'\x80', b'\xff']
# A longer key is also included: a prefix sorts below any extension of itself.
_PREFIX = b'\x80'
_EXTENDED = b'\x80\x00'


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Binary sort key orders by its bytes read as unsigned values (0x80 and 0xFF above 0x01 and 0x7F),
    ascending and descending, in a bounded range, and a key that is a prefix of another sorts below it:
    a signed comparison would invert the upper half of the range."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-binsort-')
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

    def _query(partition, **kwargs):
        resp = ddb.query(
            TableName=table,
            KeyConditionExpression=kwargs.pop('condition', 'pk = :p'),
            ExpressionAttributeValues={':p': {'S': partition}, **kwargs.pop('values', {})},
            ConsistentRead=True,
            **kwargs,
        )
        return [item['sk']['B'] for item in resp['Items']]

    # Written high-to-low so insertion order is the reverse of the expected answer.
    for sk in reversed(_UNSIGNED_ORDER):
        ddb.put_item(TableName=table, Item={'pk': {'S': 'SPAN'}, 'sk': {'B': sk}})

    got = _query('SPAN')
    assert got == _UNSIGNED_ORDER, (
        f'a Binary sort key orders by unsigned bytes, so the ascending order is '
        f'{[b.hex() for b in _UNSIGNED_ORDER]!r}; got {[b.hex() for b in got]!r}. Leading 0x80 or '
        f'0xff indicates a signed byte comparison'
    )

    descending = _query('SPAN', ScanIndexForward=False)
    assert descending == list(reversed(_UNSIGNED_ORDER)), (
        f'ScanIndexForward=False must return exactly the reverse: expected '
        f'{[b.hex() for b in reversed(_UNSIGNED_ORDER)]!r}, got '
        f'{[b.hex() for b in descending]!r}'
    )

    # A range whose upper bound is 0x7f admits only the two keys below the signed boundary.
    bounded = _query(
        'SPAN',
        condition='pk = :p AND sk <= :hi',
        values={':hi': {'B': b'\x7f'}},
    )
    assert bounded == [b'\x01', b'\x7f'], (
        f'a sort-key range bounded at 0x7f must admit 01 and 7f and exclude 80 and ff: got '
        f'{[b.hex() for b in bounded]!r}'
    )

    # --- a prefix sorts below its own extension ---
    for sk in (_EXTENDED, _PREFIX):
        ddb.put_item(TableName=table, Item={'pk': {'S': 'PREFIX'}, 'sk': {'B': sk}})
    prefix_order = _query('PREFIX')
    assert prefix_order == [_PREFIX, _EXTENDED], (
        f'a Binary key that is a prefix of another sorts below it: expected '
        f'{[_PREFIX.hex(), _EXTENDED.hex()]!r}, got {[b.hex() for b in prefix_order]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
