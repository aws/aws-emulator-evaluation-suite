"""transact-write-items-maintain-gsi-and-lsi-entries."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'transact-write-items-maintain-gsi-and-lsi-entries'
GROUP = 'transactions'
SERVICES = ['dynamodb']


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response['Error']['Code'] in not_found:
                return
            raise

    return run_undo


def _item(pk: str, sk: str, gpk: str, gsk: int, lsk: int) -> dict:
    return {'pk': {'S': pk}, 'sk': {'S': sk}, 'gpk': {'S': gpk}, 'gsk': {'N': str(gsk)}, 'lsk': {'N': str(lsk)}}


def _converged(read, want, budget_s: float = 60.0):
    """``read()`` once it equals ``want``, or its last answer when the budget runs out."""
    deadline = time.monotonic() + budget_s
    while True:
        got = read()
        if got == want or time.monotonic() > deadline:
            return got
        time.sleep(1)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactWriteItems Puts, an Update that moves the GSI and LSI keys and a Delete are each reflected
    in both secondary indexes: entries appear, move to the new key and disappear.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'N'}, {'AttributeName': 'gpk', 'AttributeType': 'S'},
            {'AttributeName': 'gsk', 'AttributeType': 'N'},
        ],
        LocalSecondaryIndexes=[{
            'IndexName': 'by-l',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        GlobalSecondaryIndexes=[{
            'IndexName': 'by-g',
            'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}, {'AttributeName': 'gsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=t), 'ResourceNotFoundException'))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 2, 'MaxAttempts': 300})
    a = _item('p', 'a', 'g1', 1, 10)
    b = _item('p', 'b', 'g1', 2, 20)
    c = _item('p', 'c', 'g1', 3, 5)

    def lsi() -> list:
        return ddb.query(
            TableName=t, IndexName='by-l', ConsistentRead=True,
            KeyConditionExpression='pk = :p', ExpressionAttributeValues={':p': {'S': 'p'}},
        )['Items']

    def gsi(gpk: str):
        return lambda: ddb.query(
            TableName=t, IndexName='by-g',
            KeyConditionExpression='gpk = :g', ExpressionAttributeValues={':g': {'S': gpk}},
        )['Items']

    ddb.transact_write_items(TransactItems=[
        {'Put': {'TableName': t, 'Item': a}},
        {'Put': {'TableName': t, 'Item': b}},
    ])
    got = lsi()
    assert got == [a, b], f'after the first transaction the LSI held {got!r}'
    got = _converged(gsi('g1'), [a, b])
    assert got == [a, b], f'after the first transaction the GSI partition g1 held {got!r}'

    ddb.transact_write_items(TransactItems=[
        {'Update': {
            'TableName': t, 'Key': {'pk': {'S': 'p'}, 'sk': {'S': 'a'}},
            'UpdateExpression': 'SET gpk = :g, lsk = :l',
            'ExpressionAttributeValues': {':g': {'S': 'g2'}, ':l': {'N': '30'}},
        }},
        {'Delete': {'TableName': t, 'Key': {'pk': {'S': 'p'}, 'sk': {'S': 'b'}}}},
        {'Put': {'TableName': t, 'Item': c}},
    ])
    moved = _item('p', 'a', 'g2', 1, 30)
    got = lsi()
    assert got == [c, moved], f'after the second transaction the LSI held {got!r}'
    got = _converged(gsi('g1'), [c])
    assert got == [c], f'after the second transaction the GSI partition g1 held {got!r}'
    got = _converged(gsi('g2'), [moved])
    assert got == [moved], f'after the second transaction the GSI partition g2 held {got!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
