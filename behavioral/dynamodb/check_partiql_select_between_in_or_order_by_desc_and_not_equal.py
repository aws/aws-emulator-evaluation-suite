"""partiql-select-between-in-or-order-by-desc-and-not-equal."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-select-between-in-or-order-by-desc-and-not-equal"
GROUP = 'partiql'
SERVICES = ['dynamodb']

# (sort key, hue, fit) in partition 'A'; None means the attribute is absent from the item.
_ROWS_A = [
    (1, 'red', None),     # matches the filter, but sits below BETWEEN's lower bound
    (2, 'red', None),     # lower bound itself: BETWEEN is inclusive
    (3, 'green', 'L'),    # only the OR's right arm matches
    (4, 'green', 'S'),    # neither arm matches
    (5, None, 'L'),       # hue absent; the OR's right arm matches
    (6, 'blue', None),    # upper bound itself
    (7, 'blue', None),    # matches the filter, but sits above BETWEEN's upper bound
]
# A sibling partition holding an item that would match every non-key predicate.
_ROWS_B = [(3, 'red', 'L')]


def _item(pk, sk, hue, fit):
    item = {'pk': {'S': pk}, 'sk': {'N': str(sk)}}
    if hue is not None:
        item['hue'] = {'S': hue}
    if fit is not None:
        item['fit'] = {'S': fit}
    return item


def _select_all(ddb, statement):
    """Every item the statement returns, following NextToken (IN results page at 10 items)."""
    items, token = [], None
    while True:
        kwargs = {'Statement': statement, 'ConsistentRead': True}
        if token:
            kwargs['NextToken'] = token
        page = ddb.execute_statement(**kwargs)
        items.extend(page['Items'])
        token = page.get('NextToken')
        if not token:
            return items


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SELECT combining pk equality, sort-key BETWEEN, IN and OR returns exactly the matching items in
    ORDER BY ... DESC order, and a <> filter also keeps an item that lacks the attribute.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.select.html
    https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-operators.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlsel-')
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'N'},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 60})

    for sk, hue, fit in _ROWS_A:
        ddb.put_item(TableName=table, Item=_item('A', sk, hue, fit))
    for sk, hue, fit in _ROWS_B:
        ddb.put_item(TableName=table, Item=_item('B', sk, hue, fit))

    # Leg 1: pk equality AND sk BETWEEN AND (IN list OR equality), ordered by sk descending.
    combined = _select_all(ddb, (
        f'SELECT * FROM "{table}" WHERE pk = \'A\' AND sk BETWEEN 2 AND 6 '
        f'AND (hue IN [\'red\', \'blue\'] OR fit = \'L\') ORDER BY sk DESC'
    ))
    want = [_item('A', sk, hue, fit) for sk, hue, fit in sorted(_ROWS_A, reverse=True)
            if 2 <= sk <= 6 and (hue in ('red', 'blue') or fit == 'L')]
    got_keys = [(i['pk']['S'], i['sk']['N']) for i in combined]
    assert [i['sk']['N'] for i in want] == ['6', '5', '3', '2'], 'fixture drifted from the claim'
    assert got_keys == [('A', '6'), ('A', '5'), ('A', '3'), ('A', '2')], (
        f'pk = A AND sk BETWEEN 2 AND 6 AND (hue IN [red, blue] OR fit = L) ORDER BY sk DESC must '
        f'return sort keys 6, 5, 3, 2 in that order (both bounds inclusive, each OR arm alone '
        f'admitting an item, nothing from partition B), got {got_keys!r}'
    )
    assert combined == want, (
        f'the selected items must come back whole and unaltered.\nwant: {want!r}\ngot:  {combined!r}'
    )

    # Leg 2: the same predicate without ORDER BY comes back in ascending sort-key order, so the
    # DESC above is a reversal the engine performed, not the natural order.
    natural = _select_all(ddb, (
        f'SELECT * FROM "{table}" WHERE pk = \'A\' AND sk BETWEEN 2 AND 6 '
        f'AND (hue IN [\'red\', \'blue\'] OR fit = \'L\')'
    ))
    natural_keys = [i['sk']['N'] for i in natural]
    assert natural_keys == ['2', '3', '5', '6'], (
        f'without ORDER BY a single-partition SELECT returns ascending sort-key order; got '
        f'{natural_keys!r}'
    )

    # Leg 3: <> keeps every item whose hue is not red. Item sk=5 has no hue at all, and real AWS
    # returns it: a missing attribute is "not equal" to the literal, as in a DynamoDB
    # condition or filter expression.
    not_red = _select_all(ddb, f'SELECT * FROM "{table}" WHERE pk = \'A\' AND hue <> \'red\'')
    not_red_keys = [i['sk']['N'] for i in not_red]
    assert not_red_keys == ['3', '4', '5', '6', '7'], (
        f"pk = A AND hue <> 'red' must return, in ascending sort-key order, the items whose hue is "
        f"not red (3, 4, 6, 7) and the item stored without hue (5), and filter the red ones (1, 2); "
        f'got {not_red_keys!r}'
    )
    want_not_red = [_item('A', sk, hue, fit) for sk, hue, fit in _ROWS_A if hue != 'red']
    assert not_red == want_not_red, (
        f'the <> result must be the whole, unaltered items.\nwant: {want_not_red!r}\n'
        f'got:  {not_red!r}'
    )

    # Leg 4: IS MISSING isolates exactly the hue-less item, so <> admitted sk=5 as an item with
    # no hue, not because it holds some other hue value.
    missing = _select_all(ddb, f'SELECT * FROM "{table}" WHERE pk = \'A\' AND hue IS MISSING')
    missing_keys = [i['sk']['N'] for i in missing]
    assert missing_keys == ['5'], (
        f'pk = A AND hue IS MISSING must return exactly the item stored without hue (5), got '
        f'{missing_keys!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
