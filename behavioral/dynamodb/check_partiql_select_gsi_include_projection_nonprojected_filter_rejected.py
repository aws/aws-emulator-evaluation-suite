"""partiql-select-gsi-include-projection-nonprojected-filter-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-select-gsi-include-projection-nonprojected-filter-rejected"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_INDEX = 'gsi1'
_PROJECTED = 'proj_attr'
_NOT_PROJECTED = 'not_proj_attr'


def _deadline(ctx, cap_s):
    """A poll's stop time: cap_s from now, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    budget_s = cap_s if left is None else max(1.0, min(cap_s, left - 5.0))
    return time.monotonic() + budget_s


def _error_code(fn) -> str:
    """The Error.Code and Error.Message ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the statement to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A PartiQL SELECT on a GSI with an index-key equality and a WHERE term on an attribute the
    INCLUDE-projection index does not project is a ValidationException; the same statement filtering
    a projected attribute narrows the index's own items and leaves them unwritten.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.select.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlincl-')
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
    assert gsi_status == 'ACTIVE', f'{_INDEX} never became ACTIVE: {gsi_status!r}'

    ddb.put_item(TableName=table, Item={
        'pk': {'S': 'P1'}, 'sk': {'S': 's1'}, 'gpk': {'S': 'g1'}, 'gsk': {'S': 'a'},
        _PROJECTED: {'S': 'match'}, _NOT_PROJECTED: {'S': 'np1'},
    })
    ddb.put_item(TableName=table, Item={
        'pk': {'S': 'P2'}, 'sk': {'S': 's2'}, 'gpk': {'S': 'g1'}, 'gsk': {'S': 'b'},
        _PROJECTED: {'S': 'other'}, _NOT_PROJECTED: {'S': 'np2'},
    })

    # Positive control: the GSI partition key equality alone must see BOTH items before the
    # projected-attribute filter below can prove it narrowed the set rather than returning
    # everything by coincidence.
    both = []
    deadline = _deadline(ctx, 60.0)
    while time.monotonic() < deadline:
        both = ddb.execute_statement(
            Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE gpk = 'g1'",
        ).get('Items', [])
        if len(both) == 2:
            break
    assert len(both) == 2, f'the index must hold both items before the filter can narrow them: {both!r}'

    # A WHERE term on an attribute the INCLUDE projection does not project is rejected, not
    # silently ignored or served from the base table.
    code, message = _error_code(lambda: ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE gpk = 'g1' AND {_NOT_PROJECTED} = 'np1'",
    ))
    assert code == 'ValidationException', (
        f'a WHERE term on a non-projected attribute of an INCLUDE-projection index must be '
        f'refused with ValidationException, got {code}: {message!r}'
    )
    assert message == (
        f'One or more parameter values were invalid: Secondary index {_INDEX} does not project '
        f'one or more filter attributes: [{_NOT_PROJECTED}]'
    ), f"expected AWS's exact ValidationException message, got {message!r}"

    # The same statement filtering on the PROJECTED attribute instead is legal and narrows the
    # two-item index down to the single matching item.
    filtered = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE gpk = 'g1' AND {_PROJECTED} = 'match'",
    ).get('Items', [])
    assert len(filtered) == 1, (
        f'a WHERE term on a projected attribute must narrow the 2-item index to the 1 matching '
        f'row, got {len(filtered)} items: {filtered!r}'
    )
    assert filtered[0]['pk'] == {'S': 'P1'}, f"expected the surviving item's pk to be P1, got {filtered[0].get('pk')!r}"
    assert filtered[0][_PROJECTED] == {'S': 'match'}, f'expected {_PROJECTED}=match, got {filtered[0].get(_PROJECTED)!r}'

    # The rejected SELECT is read-only: both base-table items are exactly as written, proving
    # the refusal above had no side effect to undo.
    kept = ddb.get_item(TableName=table, Key={'pk': {'S': 'P1'}, 'sk': {'S': 's1'}}, ConsistentRead=True)['Item']
    assert kept == {
        'pk': {'S': 'P1'}, 'sk': {'S': 's1'}, 'gpk': {'S': 'g1'}, 'gsk': {'S': 'a'},
        _PROJECTED: {'S': 'match'}, _NOT_PROJECTED: {'S': 'np1'},
    }, f'the rejected SELECT must not have written anything; item now reads {kept!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
