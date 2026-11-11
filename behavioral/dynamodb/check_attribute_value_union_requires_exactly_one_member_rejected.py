"""attribute-value-union-requires-exactly-one-member-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attribute-value-union-requires-exactly-one-member-rejected"
GROUP = 'representation'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error_code(fn, what: str) -> tuple[str, str]:
    """Return the error code and message `fn` raises; raise if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AttributeValue with zero or two type members is refused ValidationException at every depth
    (top level, inside an M, inside an L) with the exact message, and no refused write lands.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-union-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Positive control: the same shapes with arity exactly one are accepted and round-trip, so the
    # rejections below are attributable to the arity and not to the nesting or to the table.
    ddb.put_item(TableName=t, Item={
        'pk': {'S': 'legal'},
        'flat': {'S': 'x'},
        'nested': {'M': {'inner': {'S': 'x'}}},
        'listed': {'L': [{'S': 'x'}, {'N': '1'}]},
    })
    ctl = ddb.get_item(TableName=t, Key={'pk': {'S': 'legal'}}, ConsistentRead=True).get('Item', {})
    assert ctl.get('flat') == {'S': 'x'}, f'control: flat single-member value, got {ctl.get("flat")!r}'
    assert ctl.get('nested') == {'M': {'inner': {'S': 'x'}}}, (
        f'control: single-member value nested in an M, got {ctl.get("nested")!r}'
    )
    assert ctl.get('listed') == {'L': [{'S': 'x'}, {'N': '1'}]}, (
        f'control: single-member values inside an L, got {ctl.get("listed")!r}'
    )

    empty = 'Supplied AttributeValue is empty, must contain exactly one of the supported datatypes'
    two = ('Supplied AttributeValue has more than one datatypes set, must contain exactly one of '
           'the supported datatypes')
    cases = {
        'av-zero': ('zero type members at the top of the item',
                    {'pk': {'S': 'av-zero'}, 'a': {}}, empty),
        'av-two': ('two type members at the top of the item',
                   {'pk': {'S': 'av-two'}, 'a': {'S': 'x', 'N': '1'}}, two),
        'av-zero-in-m': ('zero type members nested inside an M',
                         {'pk': {'S': 'av-zero-in-m'}, 'm': {'M': {'inner': {}}}}, empty),
        'av-two-in-m': ('two type members nested inside an M',
                        {'pk': {'S': 'av-two-in-m'}, 'm': {'M': {'inner': {'S': 'x', 'BOOL': True}}}},
                        two),
        'av-zero-in-l': ('zero type members as an element of an L',
                         {'pk': {'S': 'av-zero-in-l'}, 'l': {'L': [{}]}}, empty),
    }
    for _key, (why, item, expected_message) in cases.items():
        code, message = _error_code(lambda item=item: ddb.put_item(TableName=t, Item=item),
                                    f'PutItem with an AttributeValue carrying {why}')
        assert code == ERR_VALIDATION, (
            f'an AttributeValue with {why} is not a legal union value and must be refused '
            f'{ERR_VALIDATION}, got {code!r}'
        )
        assert message == expected_message, (
            f'an AttributeValue with {why}: expected the message {expected_message!r}, got {message!r}'
        )

    # Effect absent: a read finds nothing at each refused key, so no malformed union was coerced
    # into a stored item.
    for key, (why, _item, _message) in cases.items():
        got = ddb.get_item(TableName=t, Key={'pk': {'S': key}}, ConsistentRead=True)
        assert 'Item' not in got, (
            f'the write refused for {why} must leave nothing behind at pk={key!r}, got '
            f'{got.get("Item")!r}'
        )
    scanned = ddb.scan(TableName=t, ConsistentRead=True, Select='COUNT')
    assert scanned['Count'] == 1, (
        f'only the single control item may exist after five refused writes, got '
        f'{scanned["Count"]!r} items'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
