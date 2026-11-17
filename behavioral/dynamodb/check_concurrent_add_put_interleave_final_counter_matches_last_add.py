"""concurrent-add-put-interleave-final-counter-matches-last-add."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-add-put-interleave-final-counter-matches-last-add"
GROUP = 'concurrency'
SERVICES = ['dynamodb']

_NUM_ADDS = 10
_NUM_PUTS = 10
_KEY = {'pk': {'S': 'k'}}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Interleaved full-item PutItem resets and ADD increments on one key leave a final item
    with exactly {pk,a,b}; a is either 0 (the last applied write was the Put) or equal to the
    UPDATED_NEW some ADD call actually returned, matching DynamoDB's per-item serialisation.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-addput-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'k'}, 'a': {'N': '0'}, 'b': {'S': 'init'}})

    def _add():
        resp = ddb.update_item(
            TableName=table, Key=_KEY,
            UpdateExpression='ADD a :one',
            ExpressionAttributeValues={':one': {'N': '1'}},
            ReturnValues='UPDATED_NEW',
        )
        return ('add', int(resp['Attributes']['a']['N']))

    def _put():
        ddb.put_item(TableName=table, Item={'pk': {'S': 'k'}, 'a': {'N': '0'}, 'b': {'S': 'put'}})
        return ('put', None)

    fns = [_add if i % 2 == 0 else _put for i in range(_NUM_ADDS + _NUM_PUTS)]
    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        results = [f.result() for f in [pool.submit(fn) for fn in fns]]

    add_values = [v for kind, v in results if kind == 'add']
    assert len(add_values) == _NUM_ADDS, (
        f'expected {_NUM_ADDS} ADD results, got {len(add_values)}: {add_values!r}'
    )

    final = ddb.get_item(TableName=table, Key=_KEY, ConsistentRead=True)['Item']
    assert set(final.keys()) == {'pk', 'a', 'b'}, (
        f'final item carries {sorted(final.keys())!r}, expected exactly pk, a and b'
    )
    b_val = final['b']['S']
    assert b_val in ('init', 'put'), f"final b was {b_val!r}, expected 'init' or 'put'"
    a_val = int(final['a']['N'])
    assert 0 <= a_val <= _NUM_ADDS, (
        f'final a={a_val!r} is outside the possible range 0..{_NUM_ADDS}'
    )

    if a_val == 0:
        assert b_val == 'put', (
            f"final a=0 can only follow a Put reset, but b={b_val!r}, expected 'put'"
        )
    else:
        assert a_val in add_values, (
            f'final a={a_val!r} matches none of the UPDATED_NEW values the ADD calls returned '
            f'({sorted(add_values)!r}); the stored counter must equal the value the last applied '
            f'ADD actually returned'
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
