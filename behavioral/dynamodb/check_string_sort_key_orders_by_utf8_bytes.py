"""string-sort-key-orders-by-utf8-bytes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "string-sort-key-orders-by-utf8-bytes"
GROUP = 'ordering'
SERVICES = ['dynamodb']

# Three sort keys whose UTF-8 byte order and UTF-16 code-unit order disagree. In UTF-8 the leading
# bytes are EE, EF and F0, so this is the ascending order. Encoded as UTF-16 the third is a
# surrogate pair beginning D83D, which is numerically BELOW the other two, so a comparison over
# UTF-16 code units -- the natural string comparison in several runtimes -- sorts it FIRST.
_PRIVATE_USE = '\ue000'
_REPLACEMENT = '\ufffd'
_SUPPLEMENTARY = '\U0001f600'
_UTF8_ORDER = [_PRIVATE_USE, _REPLACEMENT, _SUPPLEMENTARY]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A String sort key orders by UTF-8 bytes: a supplementary-plane character sorts above a private-use and a
    replacement code point, a reverse Query returns the reverse order, and a BETWEEN range returns the two BMP keys.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-utf8sort-')
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Written in an order that is neither the UTF-8 nor the UTF-16 order, so insertion order cannot
    # be mistaken for either answer.
    for sk in (_SUPPLEMENTARY, _PRIVATE_USE, _REPLACEMENT):
        ddb.put_item(TableName=table, Item={'pk': {'S': 'ORD'}, 'sk': {'S': sk}})

    ascending = ddb.query(
        TableName=table,
        KeyConditionExpression='pk = :p',
        ExpressionAttributeValues={':p': {'S': 'ORD'}},
        ConsistentRead=True,
    )
    got = [item['sk']['S'] for item in ascending['Items']]
    assert got == _UTF8_ORDER, (
        f'a String sort key orders by UTF-8 bytes, so the ascending order of these three code '
        f'points is {[hex(ord(c)) for c in _UTF8_ORDER]!r}; got '
        f'{[hex(ord(c)) for c in got]!r}. Leading the supplementary character indicates a '
        f'comparison over UTF-16 code units rather than UTF-8 bytes'
    )

    descending = ddb.query(
        TableName=table,
        KeyConditionExpression='pk = :p',
        ExpressionAttributeValues={':p': {'S': 'ORD'}},
        ScanIndexForward=False,
        ConsistentRead=True,
    )
    reversed_got = [item['sk']['S'] for item in descending['Items']]
    assert reversed_got == list(reversed(_UTF8_ORDER)), (
        f'ScanIndexForward=False must return exactly the reverse of the ascending order: expected '
        f'{[hex(ord(c)) for c in reversed(_UTF8_ORDER)]!r}, got '
        f'{[hex(ord(c)) for c in reversed_got]!r}'
    )

    # A range bounded at the BMP replacement code point excludes the supplementary key above it.
    bounded = ddb.query(
        TableName=table,
        KeyConditionExpression='pk = :p AND sk <= :hi',
        ExpressionAttributeValues={':p': {'S': 'ORD'}, ':hi': {'S': _REPLACEMENT}},
        ConsistentRead=True,
    )
    bounded_got = [item['sk']['S'] for item in bounded['Items']]
    assert bounded_got == [_PRIVATE_USE, _REPLACEMENT], (
        f'a sort-key range bounded at {hex(ord(_REPLACEMENT))!r} must include the two keys at or '
        f'below it in UTF-8 order and exclude the supplementary one: expected '
        f'{[hex(ord(_PRIVATE_USE)), hex(ord(_REPLACEMENT))]!r}, got '
        f'{[hex(ord(c)) for c in bounded_got]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
