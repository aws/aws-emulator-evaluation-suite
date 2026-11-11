"""plain-write-racing-a-transaction-rejected."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "plain-write-racing-a-transaction-rejected"
GROUP = 'transactions'
SERVICES = ['dynamodb']

ERR_CONFLICT = 'TransactionConflictException'
_TRANSACTORS = 8
_PLAIN_WRITERS = 8
#: Contention rounds run before the check settles for the counter assertion alone.
_MAX_ROUNDS = 25
#: Wall bound on the contention rounds; the run budget caps it further.
_CONTENTION_S = 120


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 30 s so the final
    reads and the asserts still run."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 30.0))


def _code(exc):
    return exc.response.get('Error', {}).get('Code')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A singleton UpdateItem racing TransactWriteItems on one key is refused only with
    TransactionConflictException, a losing transaction is cancelled with the exact [TransactionConflict]
    message, and the final counter equals exactly the accepted writes.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-txrace-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})

    key = {'pk': {'S': 'CONTENDED'}}
    ddb.put_item(TableName=table, Item={'pk': {'S': 'CONTENDED'}, 'hits': {'N': '0'}})

    bump = {
        'TableName': table,
        'Key': key,
        'UpdateExpression': 'ADD hits :one',
        'ExpressionAttributeValues': {':one': {'N': '1'}},
    }

    transact_errors = []

    def _transact(_):
        try:
            ddb.transact_write_items(TransactItems=[{'Update': dict(bump)}])
            return ('transact', None)
        except ClientError as exc:
            transact_errors.append(exc.response.get('Error', {}))
            return ('transact', _code(exc))

    def _plain(_):
        try:
            ddb.update_item(**bump)
            return ('plain', None)
        except ClientError as exc:
            return ('plain', _code(exc))

    accepted = 0
    plain_codes = []
    transact_codes = []
    rounds = 0
    deadline = time.monotonic() + _budget_s(ctx, _CONTENTION_S)
    # A run with no refused plain write still passes: the exact counter catches lost writes.
    while (rounds < _MAX_ROUNDS and ERR_CONFLICT not in plain_codes
           and (rounds == 0 or time.monotonic() < deadline)):
        rounds += 1
        calls = [_transact] * _TRANSACTORS + [_plain] * _PLAIN_WRITERS
        with ThreadPoolExecutor(max_workers=len(calls)) as pool:
            outcomes = list(pool.map(lambda fn: fn(None), calls))
        accepted += sum(1 for _, code in outcomes if code is None)
        plain_codes.extend(c for kind, c in outcomes if kind == 'plain' and c is not None)
        transact_codes.extend(c for kind, c in outcomes if kind == 'transact' and c is not None)

    unexpected = {c for c in plain_codes if c != ERR_CONFLICT}
    assert not unexpected, (
        f'a singleton write that loses to a transaction is refused with {ERR_CONFLICT} and '
        f'nothing else; also saw {sorted(unexpected)!r}'
    )
    assert all(c == 'TransactionCanceledException' for c in transact_codes), (
        f'a transaction that loses is CANCELLED, not conflicted at the top level; got '
        f'{sorted(set(transact_codes))!r}'
    )
    cancelled = 'Transaction cancelled, please refer cancellation reasons for specific reasons [TransactionConflict]'
    messages = [e.get('Message') for e in transact_errors]
    assert messages == [cancelled] * len(messages), (
        f'a transaction that loses the race is cancelled for TransactionConflict; got '
        f'{sorted(set(messages))!r}'
    )

    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
    assert final['hits']['N'] == str(accepted), (
        f'the counter must equal the accepted writes exactly: a refused write must add nothing '
        f'and an accepted one must not be lost. Got {final["hits"]["N"]!r}, expected '
        f'{accepted!r} with {len(plain_codes)!r} refusals and {len(transact_codes)!r} '
        f'cancellations'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
