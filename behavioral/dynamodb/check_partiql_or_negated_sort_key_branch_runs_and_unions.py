"""partiql-or-negated-sort-key-branch-runs-and-unions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = 'partiql-or-negated-sort-key-branch-runs-and-unions'
GROUP = 'partiql'
SERVICES = ['dynamodb']

_SORT_KEYS = ['1', '2', '3']


def _item(pk, sk):
    return {'pk': {'S': pk}, 'sk': {'S': sk}}


def _select_all(ddb, statement):
    """Every item the statement returns, following NextToken."""
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


def _sk_set(items):
    return sorted(i['sk']['S'] for i in items)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A WHERE clause ORing a negated sort-key branch beside another sort-key branch on the
    same partition key runs and returns the union, for every documented negated form.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlor-')
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
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 60})

    for sk in _SORT_KEYS:
        ddb.put_item(TableName=table, Item=_item('p', sk))
    # A sibling partition that would match every branch below, to prove no cross-partition leak.
    ddb.put_item(TableName=table, Item=_item('q', '1'))
    ddb.put_item(TableName=table, Item=_item('q', '2'))

    def select(where):
        return _sk_set(_select_all(ddb, f'SELECT * FROM "{table}" WHERE {where}'))

    # Positive control: a plain pk+sk equality still runs and returns exactly that one item,
    # proving the table and the query path work before any OR/NOT form is exercised.
    plain = select("pk = 'p' AND sk = '2'")
    assert plain == ['2'], f"pk = 'p' AND sk = '2' must return exactly sk 2, got {plain!r}"

    # NOT sk = <literal> OR sk = <literal>: the negated branch admits 2 and 3, the plain branch
    # re-admits 2; the union is {2, 3}.
    got = select("pk = 'p' AND NOT sk = '1' OR pk = 'p' AND sk = '2'")
    assert got == ['2', '3'], (
        f"pk = 'p' AND NOT sk = '1' OR pk = 'p' AND sk = '2' must return the union {{2, 3}}, "
        f"got {got!r}"
    )

    # The same claim written with NOT wrapping a parenthesised equality must parse and answer
    # identically to the unparenthesised NOT above.
    parenthesised = select("pk = 'p' AND NOT (sk = '1') OR pk = 'p' AND sk = '2'")
    assert parenthesised == ['2', '3'], (
        f"pk = 'p' AND NOT (sk = '1') OR pk = 'p' AND sk = '2' must return the union {{2, 3}}, "
        f"got {parenthesised!r}"
    )

    # sk <> <literal> is itself a negated comparison; it must union the same way as NOT sk =.
    not_equal = select("pk = 'p' AND sk <> '1' OR pk = 'p' AND sk = '2'")
    assert not_equal == ['2', '3'], (
        f"pk = 'p' AND sk <> '1' OR pk = 'p' AND sk = '2' must return the union {{2, 3}}, "
        f"got {not_equal!r}"
    )

    # NOT begins_with: the sort keys are single digits, so begins_with(sk, '1') matches only '1'
    # and its negation admits 2 and 3 — the same union as the equality forms above.
    not_begins = select("pk = 'p' AND NOT begins_with(sk, '1') OR pk = 'p' AND sk = '2'")
    assert not_begins == ['2', '3'], (
        f"pk = 'p' AND NOT begins_with(sk, '1') OR pk = 'p' AND sk = '2' must return the union "
        f"{{2, 3}}, got {not_begins!r}"
    )

    # NOT sk IN (...): excluding two of the three keys leaves one from the negated branch, and
    # the plain branch re-admits that same key, so the union collapses to a single element —
    # distinct from the single-literal negations above, proving IN's list is honoured.
    not_in = select("pk = 'p' AND NOT sk IN ['1', '3'] OR pk = 'p' AND sk = '2'")
    assert not_in == ['2'], (
        f"pk = 'p' AND NOT sk IN ['1', '3'] OR pk = 'p' AND sk = '2' must return just {{2}}, "
        f"got {not_in!r}"
    )

    # NOT sk > <literal>: admits keys at or below the literal (here just '1'); ORed with the
    # plain sk = '2' branch the union is {1, 2}, disjoint from the equality-negation unions above.
    not_gt = select("pk = 'p' AND NOT sk > '1' OR pk = 'p' AND sk = '2'")
    assert not_gt == ['1', '2'], (
        f"pk = 'p' AND NOT sk > '1' OR pk = 'p' AND sk = '2' must return the union {{1, 2}}, "
        f"got {not_gt!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
