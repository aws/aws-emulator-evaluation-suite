"""partiql-select-index-unprojected-filter-refusal-scoped-to-key-condition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-select-index-unprojected-filter-refusal-scoped-to-key-condition"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_INDEX = 'gsi1'
_PROJECTED = 'proj_attr'
_NOT_PROJECTED = 'not_proj_attr'

_UNPROJECTED_REFUSED = (
    'ValidationException',
    f'One or more parameter values were invalid: Secondary index {_INDEX} does not project '
    f'one or more filter attributes: [{_NOT_PROJECTED}]',
)


def _deadline(ctx, cap_s):
    """A poll's stop time: cap_s from now, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    budget_s = cap_s if left is None else max(1.0, min(cap_s, left - 5.0))
    return time.monotonic() + budget_s


def expect_error(fn, code, message):
    """Assert ``fn`` raises exactly (code, message); an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        got_code, got_message = err.get('Code'), err.get('Message')
        assert got_code == code, f'expected error code {code!r}, got {got_code!r}: {got_message!r}'
        assert got_message == message, f'expected error message {message!r}, got {got_message!r}'
        return
    raise AssertionError(f'expected the statement to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A PartiQL SELECT's unprojected-filter refusal fires only with a key condition on the index
    (partition key =, IN, or = with sort-key BETWEEN), for every predicate form including OR
    nesting; with no key condition the predicate is accepted and the attribute reads as absent.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.select.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlkey-')
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gpk', 'AttributeType': 'S'},
            {'AttributeName': 'gsk', 'AttributeType': 'S'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': _INDEX,
            'KeySchema': [
                {'AttributeName': 'gpk', 'KeyType': 'HASH'},
                {'AttributeName': 'gsk', 'KeyType': 'RANGE'},
            ],
            'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': [_PROJECTED]},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 60})

    gsi_status = None
    deadline = _deadline(ctx, 180.0)
    while time.monotonic() < deadline:
        described = ddb.describe_table(TableName=table)['Table']
        gsis = {i['IndexName']: i['IndexStatus'] for i in described.get('GlobalSecondaryIndexes', [])}
        gsi_status = gsis.get(_INDEX)
        if gsi_status == 'ACTIVE':
            break
        time.sleep(2)
    assert gsi_status == 'ACTIVE', f'{_INDEX} never became ACTIVE: {gsi_status!r}'

    # Four items under one GSI partition key, each carrying both the projected and the
    # not-projected attribute in the base table -- the index just does not carry the latter.
    _ROWS = [
        ('a', 'match', 'np-a'),
        ('b', 'other', 'np-b'),
        ('c', 'other', 'np-c'),
        ('d', 'other', 'np-d'),
    ]
    for gsk, proj, not_proj in _ROWS:
        ddb.put_item(TableName=table, Item={
            'pk': {'S': f'P{gsk}'}, 'sk': {'S': 'only'}, 'gpk': {'S': 'g1'}, 'gsk': {'S': gsk},
            _PROJECTED: {'S': proj}, _NOT_PROJECTED: {'S': not_proj},
        })

    # Positive control: the index-key equality alone reaches all four rows before any filter
    # narrows or refuses them.
    all_rows = []
    deadline = _deadline(ctx, 60.0)
    while time.monotonic() < deadline:
        all_rows = ddb.execute_statement(
            Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE gpk = 'g1'",
        ).get('Items', [])
        if len(all_rows) == 4:
            break
        time.sleep(2)
    assert sorted(i['pk']['S'] for i in all_rows) == ['Pa', 'Pb', 'Pc', 'Pd'], (
        f'expected all 4 index rows before filtering, got {all_rows!r}'
    )

    # Keyed with `=` on the index partition key: every predicate form on the unprojected
    # attribute is refused, not silently ignored.
    expect_error(lambda: ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE gpk = 'g1' "
                  f"AND {_NOT_PROJECTED} IS MISSING",
    ), *_UNPROJECTED_REFUSED)
    expect_error(lambda: ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE gpk = 'g1' "
                  f"AND {_NOT_PROJECTED} IS NOT MISSING",
    ), *_UNPROJECTED_REFUSED)
    expect_error(lambda: ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE gpk = 'g1' "
                  f"AND NOT {_NOT_PROJECTED} = 'np-a'",
    ), *_UNPROJECTED_REFUSED)
    expect_error(lambda: ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE gpk = 'g1' "
                  f"AND begins_with({_NOT_PROJECTED}, 'np')",
    ), *_UNPROJECTED_REFUSED)

    # Nesting the unprojected predicate inside an OR does not exempt a keyed statement: the
    # refusal still fires with the partition-key equality present at the top level.
    expect_error(lambda: ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE gpk = 'g1' "
                  f"AND ({_NOT_PROJECTED} = 'np-a' OR {_PROJECTED} = 'match')",
    ), *_UNPROJECTED_REFUSED)

    # Keyed with IN on the index partition key: the refusal still fires.
    expect_error(lambda: ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE gpk IN ['g1'] "
                  f"AND {_NOT_PROJECTED} IS MISSING",
    ), *_UNPROJECTED_REFUSED)

    # Keyed with BETWEEN on the index sort key, alongside the partition key equality: the
    # refusal still fires.
    expect_error(lambda: ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE gpk = 'g1' "
                  f"AND gsk BETWEEN 'a' AND 'b' AND {_NOT_PROJECTED} IS MISSING",
    ), *_UNPROJECTED_REFUSED)

    # IS NOT MISSING on the PROJECTED attribute, alongside the same key condition, is accepted:
    # the refusal is specific to the unprojected attribute, not to the predicate form.
    projected_present = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE gpk = 'g1' "
                  f"AND {_PROJECTED} IS NOT MISSING",
    ).get('Items', [])
    assert sorted(i['pk']['S'] for i in projected_present) == ['Pa', 'Pb', 'Pc', 'Pd'], (
        f'IS NOT MISSING on the projected attribute must accept all 4 rows, got {projected_present!r}'
    )

    # With no key condition at all (a full index scan), the same predicate on the unprojected
    # attribute is accepted, and the attribute reads as absent: NOT x = v is true for every row.
    scanned = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE NOT {_NOT_PROJECTED} = 'np-a'",
    ).get('Items', [])
    assert sorted(i['pk']['S'] for i in scanned) == ['Pa', 'Pb', 'Pc', 'Pd'], (
        f'unkeyed NOT {_NOT_PROJECTED} = v must be accepted and match every index row '
        f'(the attribute reads as absent), got {scanned!r}'
    )

    # Two unkeyed filters, one of them on the unprojected attribute: accepted, and the
    # unprojected attribute's absence makes the equality fail for every row, even though the
    # base table item it would otherwise match does carry that exact value.
    two_filters = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE {_PROJECTED} = 'match' "
                  f"AND {_NOT_PROJECTED} = 'np-a'",
    ).get('Items', [])
    assert two_filters == [], (
        f'the unprojected attribute must read as absent even where the base item carries the '
        f'matching value, got {two_filters!r}'
    )

    # An OR with no key condition anywhere in the WHERE clause is accepted, and the branch
    # touching the unprojected attribute reads as absent (false), so only the other branch's
    # row matches.
    or_branch = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE {_NOT_PROJECTED} = 'np-a' "
                  f"OR {_PROJECTED} = 'match'",
    ).get('Items', [])
    assert len(or_branch) == 1, (
        f'an unkeyed OR touching the unprojected attribute must be accepted, matching only the '
        f'other branch\'s row, got {or_branch!r}'
    )
    assert or_branch[0]['pk'] == {'S': 'Pa'}, (
        f"expected the OR's surviving row to be pk=Pa, got {or_branch[0].get('pk')!r}"
    )

    # A sort-key BETWEEN with no partition-key equality is not a key condition on its own: the
    # statement is unkeyed, and the unprojected predicate is accepted and reads as absent (true
    # for every row BETWEEN scans), narrowing the result to the BETWEEN range alone.
    sort_between_unkeyed = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE gsk BETWEEN 'a' AND 'b' "
                  f"AND {_NOT_PROJECTED} IS MISSING",
    ).get('Items', [])
    sort_between_keys = sorted(i['pk']['S'] for i in sort_between_unkeyed)
    assert sort_between_keys == ['Pa', 'Pb'], (
        f'a sort-key BETWEEN with no partition-key equality must be accepted as unkeyed, got '
        f'{sort_between_unkeyed!r}'
    )

    # Every refused and accepted SELECT above is read-only: the base-table rows are exactly as
    # written.
    for gsk, proj, not_proj in _ROWS:
        kept = ddb.get_item(
            TableName=table, Key={'pk': {'S': f'P{gsk}'}, 'sk': {'S': 'only'}}, ConsistentRead=True,
        )['Item']
        assert kept == {
            'pk': {'S': f'P{gsk}'}, 'sk': {'S': 'only'}, 'gpk': {'S': 'g1'}, 'gsk': {'S': gsk},
            _PROJECTED: {'S': proj}, _NOT_PROJECTED: {'S': not_proj},
        }, f'no SELECT above must have written anything; item now reads {kept!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
