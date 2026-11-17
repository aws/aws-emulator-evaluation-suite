"""partiql-select-lsi-unprojected-filter-scoping-unkeyed-or-between."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-select-lsi-unprojected-filter-scoping-unkeyed-or-between"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_INDEX = 'lsi1'
_PROJECTED = 'proj_attr'
_NOT_PROJECTED = 'not_proj_attr'

_UNPROJECTED_REFUSED = (
    'ValidationException',
    f'One or more parameter values were invalid: Secondary index {_INDEX} does not project '
    f'one or more filter attributes: [{_NOT_PROJECTED}]',
)


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
    """A PartiQL SELECT on an LSI accepts an unprojected-attribute filter unless the index's
    sort key sits in a top-level AND; a key equality inside an OR branch does not count, but a
    top-level BETWEEN on the sort key does and the filter is refused.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.select.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqllsior-')
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'N'},
        ],
        LocalSecondaryIndexes=[{
            'IndexName': _INDEX,
            'KeySchema': [
                {'AttributeName': 'pk', 'KeyType': 'HASH'},
                {'AttributeName': 'lsk', 'KeyType': 'RANGE'},
            ],
            'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': [_PROJECTED]},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 60})

    # Four rows under one partition key, each carrying both the projected and the not-projected
    # attribute in the base table -- the LSI's INCLUDE projection just does not carry the latter.
    _ROWS = [
        ('s1', 1, 'other1', 'np-1'),
        ('s2', 2, 'other2', 'np-2'),
        ('s3', 3, 'match3', 'np-3'),
        ('s4', 4, 'other4', 'np-4'),
    ]
    for sk, lsk, proj, not_proj in _ROWS:
        ddb.put_item(TableName=table, Item={
            'pk': {'S': 'P'}, 'sk': {'S': sk}, 'lsk': {'N': str(lsk)},
            _PROJECTED: {'S': proj}, _NOT_PROJECTED: {'S': not_proj},
        })

    # Positive control: a projected-attribute filter with no key condition reaches the index and
    # narrows correctly, proving the unkeyed scan below is actually evaluating the WHERE clause.
    scan_projected = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE {_PROJECTED} = 'match3'",
    ).get('Items', [])
    assert sorted(i['sk']['S'] for i in scan_projected) == ['s3'], (
        f'unkeyed scan filtering on the projected attribute must match only sk=s3, got '
        f'{scan_projected!r}'
    )

    # With no key condition at all, a filter on the unprojected attribute is accepted (not
    # refused), and because the index never carries that attribute it reads as absent, so an
    # equality test against it matches nothing.
    scan_unprojected = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE {_NOT_PROJECTED} = 'np-1'",
    ).get('Items', [])
    assert scan_unprojected == [], (
        f'an unkeyed filter on the unprojected attribute must be accepted and match nothing '
        f'(the attribute reads as absent through the index), got {scan_unprojected!r}'
    )

    # An OR whose branches each carry the index's own key equality is accepted even where one
    # branch also filters on the unprojected attribute: the key equality inside an OR branch is
    # not a top-level AND key condition, so the unprojected filter is scoped as unkeyed rather
    # than refused. The branch pairing the key with the unprojected filter reads that attribute
    # as absent (false); the other branch, pairing the key with the projected attribute, matches
    # normally.
    or_branches = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE "
                  f"(pk = 'P' AND lsk = 1 AND {_NOT_PROJECTED} = 'np-1') OR "
                  f"(pk = 'P' AND lsk = 3 AND {_PROJECTED} = 'match3')",
    ).get('Items', [])
    assert sorted(i['sk']['S'] for i in or_branches) == ['s3'], (
        f"an OR with the index key inside each branch must be accepted, matching only the "
        f"branch whose filter is on the projected attribute, got {or_branches!r}"
    )

    # Positive control: the index's own key equality plus BETWEEN on its sort key, with no
    # filter, answers normally.
    between_only = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE pk = 'P' AND lsk BETWEEN 1 AND 3",
    ).get('Items', [])
    assert sorted(i['sk']['S'] for i in between_only) == ['s1', 's2', 's3'], (
        f'pk = and sort-key BETWEEN with no filter must answer with sk s1, s2 and s3, got '
        f'{between_only!r}'
    )

    # BETWEEN on the index's own sort key, at the top level alongside the partition-key equality,
    # counts as a key condition: a filter on the unprojected attribute is refused, not silently
    # evaluated as absent.
    expect_error(lambda: ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE pk = 'P' "
                  f"AND lsk BETWEEN 1 AND 3 AND {_NOT_PROJECTED} = 'np-1'",
    ), *_UNPROJECTED_REFUSED)

    # Every SELECT above, accepted or refused, is read-only: the base-table rows are exactly as
    # written.
    for sk, lsk, proj, not_proj in _ROWS:
        kept = ddb.get_item(
            TableName=table, Key={'pk': {'S': 'P'}, 'sk': {'S': sk}}, ConsistentRead=True,
        )['Item']
        assert kept == {
            'pk': {'S': 'P'}, 'sk': {'S': sk}, 'lsk': {'N': str(lsk)},
            _PROJECTED: {'S': proj}, _NOT_PROJECTED: {'S': not_proj},
        }, f'no SELECT above must have written anything; item now reads {kept!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
