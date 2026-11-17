"""query-select-all-attributes-on-partial-projection-gsi-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-select-all-attributes-on-partial-projection-gsi-rejected"
GROUP = 'validation'
SERVICES = ['dynamodb']

_KEYS_ONLY = 'keys-only-index'
_INCLUDE = 'include-index'
_NOT_ALL = (
    'One or more parameter values were invalid: Select type ALL_ATTRIBUTES is not supported for '
    'global secondary index {index} because its projection type is not ALL'
)


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table and its GSIs are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)['Table']
        if desc['TableStatus'] == 'ACTIVE' and all(
            g.get('IndexStatus') == 'ACTIVE' for g in desc.get('GlobalSecondaryIndexes', [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f'table {table} not ACTIVE before the deadline: {desc!r}')


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query with Select=ALL_ATTRIBUTES on a KEYS_ONLY or INCLUDE global secondary index is
    refused -- a GSI never fetches from the base table -- while ALL_PROJECTED_ATTRIBUTES on
    each index and ALL_ATTRIBUTES on the table itself are served."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddb-querysel-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gk', 'AttributeType': 'S'},
        ],
        GlobalSecondaryIndexes=[
            {'IndexName': _KEYS_ONLY, 'KeySchema': [{'AttributeName': 'gk', 'KeyType': 'HASH'}],
             'Projection': {'ProjectionType': 'KEYS_ONLY'}},
            {'IndexName': _INCLUDE, 'KeySchema': [{'AttributeName': 'gk', 'KeyType': 'HASH'}],
             'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['inc']}},
        ],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_active(ddb, ctx, table)

    item = {'pk': {'S': 'P'}, 'sk': {'S': 'S'}, 'gk': {'S': 'G'}, 'inc': {'S': 'i'}, 'body': {'S': 'b'}}
    ddb.put_item(TableName=table, Item=item)
    keys = {'pk': item['pk'], 'sk': item['sk'], 'gk': item['gk']}
    projected = {_KEYS_ONLY: keys, _INCLUDE: {**keys, 'inc': item['inc']}}

    for index in (_KEYS_ONLY, _INCLUDE):
        expected = _NOT_ALL.format(index=index)
        code, msg = _error(lambda index=index: ddb.query(
            TableName=table, IndexName=index, Select='ALL_ATTRIBUTES',
            KeyConditionExpression='gk = :g', ExpressionAttributeValues={':g': {'S': 'G'}},
        ))
        assert (code, msg) == ('ValidationException', expected), (
            f'Query IndexName={index!r} Select=ALL_ATTRIBUTES gave {code!r}: {msg!r}'
        )

    # Index reads are eventually consistent: poll until each index serves its projection.
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 60.0)
    for index, want in projected.items():
        while True:
            got = ddb.query(
                TableName=table, IndexName=index, Select='ALL_PROJECTED_ATTRIBUTES',
                KeyConditionExpression='gk = :g', ExpressionAttributeValues={':g': {'S': 'G'}},
            )['Items']
            if got:
                break
            assert time.monotonic() < deadline, f'Query of {index} stayed empty: {got!r}'
            time.sleep(2)
        assert got == [want], f'Query {index} ALL_PROJECTED_ATTRIBUTES returned {got!r}, expected [{want!r}]'

    full = ddb.query(
        TableName=table, Select='ALL_ATTRIBUTES', ConsistentRead=True,
        KeyConditionExpression='pk = :p', ExpressionAttributeValues={':p': {'S': 'P'}},
    )['Items']
    assert full == [item], f'Query of the table with Select=ALL_ATTRIBUTES returned {full!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
