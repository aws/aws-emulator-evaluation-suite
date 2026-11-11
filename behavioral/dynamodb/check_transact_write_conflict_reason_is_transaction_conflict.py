"""transact-write-conflict-reason-is-transaction-conflict."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-conflict-reason-is-transaction-conflict"
GROUP = 'transactions'
SERVICES = ['dynamodb']

ERR_CANCELLED = 'TransactionCanceledException'
CANCELLED_MESSAGE = ('Transaction cancelled, please refer cancellation reasons for specific reasons '
                     '[TransactionConflict, None]')
CONFLICT_MESSAGE = 'Transaction is ongoing for the item'
_WORKERS = 12


def _contend(ddb, table, worker, round_no):
    """One unconditional two-item TransactWriteItems: a key every worker shares, and a key this
    worker alone touches. Returns None on commit, (message, CancellationReasons) on a cancellation,
    and raises anything else. The second key is per-worker so only slot 0 is ever contended."""
    items = [
        {'Update': {
            'TableName': table,
            'Key': {'pk': {'S': 'HOT'}},
            'UpdateExpression': 'ADD hits :one',
            'ExpressionAttributeValues': {':one': {'N': '1'}},
        }},
        {'Update': {
            'TableName': table,
            'Key': {'pk': {'S': f'OWN#{worker}'}},
            'UpdateExpression': 'SET round_no = :r',
            'ExpressionAttributeValues': {':r': {'N': str(round_no)}},
        }},
    ]
    try:
        ddb.transact_write_items(TransactItems=items)
        return None
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != ERR_CANCELLED:
            raise
        return exc.response['Error'].get('Message'), exc.response.get('CancellationReasons')


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """One round of overlapping unconditional TransactWriteItems on a shared item may cancel some
    (zero is allowed); every cancellation carries the exact message, a positional reasons list with
    TransactionConflict on the shared slot only, and the shared counter equals the commits.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-txconflict-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={'pk': {'S': 'HOT'}, 'hits': {'N': '0'}})
    for worker in range(_WORKERS):
        ddb.put_item(TableName=table,
                     Item={'pk': {'S': f'OWN#{worker}'}, 'round_no': {'N': '0'}})

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        outcomes = list(pool.map(lambda w: _contend(ddb, table, w, 1), range(_WORKERS)))
    committed = sum(1 for o in outcomes if o is None)
    cancellations = [o for o in outcomes if o is not None]

    for message, reasons in cancellations:
        assert message == CANCELLED_MESSAGE, (
            f'expected the cancellation message {CANCELLED_MESSAGE!r}, got {message!r}'
        )
        assert isinstance(reasons, list) and len(reasons) == 2, (
            f'CancellationReasons must carry one entry per TransactItem, in request order: '
            f'expected 2 entries for a 2-item transaction, got {reasons!r}'
        )
        assert reasons[0].get('Code') == 'TransactionConflict', (
            f'the contended item was refused with no ConditionExpression in the request, so the '
            f'only reason real AWS gives is TransactionConflict; got '
            f'{reasons[0].get("Code")!r} in {reasons!r}'
        )
        assert reasons[0].get('Message') == CONFLICT_MESSAGE, (
            f'the contended item must carry {CONFLICT_MESSAGE!r}, got {reasons[0].get("Message")!r}'
        )
        assert reasons[1].get('Code') in (None, 'None'), (
            f'the second item in this request is touched by no other worker, so it was not the '
            f'cause and its slot must carry no reason code: got {reasons[1]!r}. A code here means '
            f'the reasons list is not positional'
        )

    hot = ddb.get_item(TableName=table, Key={'pk': {'S': 'HOT'}}, ConsistentRead=True)['Item']
    assert hot['hits']['N'] == str(committed), (
        f'the counter must record exactly the committed transactions and nothing from the '
        f'cancelled ones: got {hot["hits"]["N"]!r}, expected {committed!r} after '
        f'{len(cancellations)!r} cancellations'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
