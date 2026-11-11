"""partiql-select-index-qualifier-projection-follows-index-type."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-select-index-qualifier-projection-follows-index-type"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_GSI = 'gsi-keys-only'
_LSI = 'lsi-keys-only'


def _deadline(ctx, cap_s):
    """A poll's stop time: cap_s from now, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    budget_s = cap_s if left is None else max(1.0, min(cap_s, left - 5.0))
    return time.monotonic() + budget_s


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the statement to be rejected, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """A PartiQL SELECT through a KEYS_ONLY GSI qualifier projects only its key and the table
    keys; through a KEYS_ONLY LSI it table-fetches an unprojected attribute named in the SELECT
    list; naming that same attribute through the GSI is refused.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlidx-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gsiPk2', 'AttributeType': 'S'},
            {'AttributeName': 'lsiSk', 'AttributeType': 'N'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': _GSI,
            'KeySchema': [{'AttributeName': 'gsiPk2', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        LocalSecondaryIndexes=[{
            'IndexName': _LSI,
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsiSk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})

    gsi_status = None
    deadline = _deadline(ctx, 300.0)
    while time.monotonic() < deadline:
        described = ddb.describe_table(TableName=table)['Table']
        gsis = {i['IndexName']: i['IndexStatus'] for i in described.get('GlobalSecondaryIndexes', [])}
        gsi_status = gsis.get(_GSI)
        if gsi_status == 'ACTIVE':
            break
        time.sleep(2)
    assert gsi_status == 'ACTIVE', f'{_GSI} never became ACTIVE within the deadline: {gsi_status!r}'

    ddb.put_item(TableName=table, Item={
        'pk': {'S': 'p1'}, 'sk': {'S': 's1'}, 'gsiPk2': {'S': 'g1'}, 'lsiSk': {'N': '5'},
        'extra': {'S': 'unprojected-value'},
    })

    # The GSI is eventually consistent, so poll for the write to appear before grading its shape.
    gsi_items = []
    deadline = _deadline(ctx, 120.0)
    while time.monotonic() < deadline:
        gsi_items = ddb.execute_statement(
            Statement=f"SELECT * FROM \"{table}\".\"{_GSI}\" WHERE gsiPk2 = 'g1'",
        ).get('Items', [])
        if gsi_items:
            break
        time.sleep(2)
    assert len(gsi_items) == 1, f'expected exactly one item through the GSI, got {gsi_items!r}'
    assert set(gsi_items[0]) == {'gsiPk2', 'pk', 'sk'}, (
        f'a SELECT * through a KEYS_ONLY GSI must project only the GSI key and the table keys, '
        f'got {sorted(gsi_items[0])!r}'
    )
    assert gsi_items[0] == {'gsiPk2': {'S': 'g1'}, 'pk': {'S': 'p1'}, 'sk': {'S': 's1'}}, (
        f'unexpected GSI key/table-key values: {gsi_items[0]!r}'
    )

    # The LSI supports a strongly consistent read, so a table fetch through it needs no poll.
    lsi_items = ddb.execute_statement(
        Statement=f"SELECT extra FROM \"{table}\".\"{_LSI}\" WHERE pk = 'p1'",
        ConsistentRead=True,
    ).get('Items', [])
    assert len(lsi_items) == 1, f'expected exactly one item through the LSI, got {lsi_items!r}'
    assert lsi_items[0] == {'extra': {'S': 'unprojected-value'}}, (
        f"naming 'extra' in the SELECT list through a KEYS_ONLY LSI must table-fetch it from "
        f'the base table, got {lsi_items[0]!r}'
    )

    # The same attribute, named through the GSI instead of the LSI, is refused: a GSI has no
    # base table to fetch from.
    code, message = _error(lambda: ddb.execute_statement(
        Statement=f"SELECT extra FROM \"{table}\".\"{_GSI}\" WHERE gsiPk2 = 'g1'",
        ConsistentRead=False,
    ))
    assert code == 'ValidationException', (
        f"naming 'extra' in the SELECT list through the KEYS_ONLY GSI must be refused with "
        f'ValidationException, got {code}: {message!r}'
    )
    assert message == (
        f'One or more parameter values were invalid: Global secondary index {_GSI} does not '
        f'project [extra]'
    ), f"expected AWS's exact ValidationException message, got {message!r}"

    # The rejected SELECT is read-only: the base item is exactly as written.
    kept = ddb.get_item(TableName=table, Key={'pk': {'S': 'p1'}, 'sk': {'S': 's1'}}, ConsistentRead=True)['Item']
    assert kept == {
        'pk': {'S': 'p1'}, 'sk': {'S': 's1'}, 'gsiPk2': {'S': 'g1'}, 'lsiSk': {'N': '5'},
        'extra': {'S': 'unprojected-value'},
    }, f'the rejected SELECT must not have written anything; item now reads {kept!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
