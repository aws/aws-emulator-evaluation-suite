"""transact-get-items-never-observes-a-torn-transfer."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-get-items-never-observes-a-torn-transfer"
GROUP = 'concurrency'
SERVICES = ['dynamodb']

_MOVES = 40
_READS = 40
_TOTAL = 100
_AMOUNT = 10
ERR_TRANSACTION_CANCELED = 'TransactionCanceledException'
_TAGS_KV = [
    {'Key': 'sim2real:managed', 'Value': 'true'},
    {'Key': 'sim2real:prefix', 'Value': 'sim2real-behav'},
]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """While one thread alternates TransactWriteItems transfers between two items, every concurrent
    TransactGetItems sees the invariant total; the final balances also return to their start.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-torn-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=_TAGS_KV,
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for name in ('A', 'B'):
        ddb.put_item(TableName=table,
                     Item={'pk': {'S': name}, 'bal': {'N': str(_TOTAL // 2)}})

    def _move(src: str, dst: str) -> str | None:
        """One transfer, retried only while the service reports a transaction CONFLICT."""
        for attempt in range(30):
            try:
                ddb.transact_write_items(TransactItems=[
                    {'Update': {'TableName': table, 'Key': {'pk': {'S': src}},
                                'UpdateExpression': 'SET bal = bal - :d',
                                'ConditionExpression': 'bal >= :d',
                                'ExpressionAttributeValues': {':d': {'N': str(_AMOUNT)}}}},
                    {'Update': {'TableName': table, 'Key': {'pk': {'S': dst}},
                                'UpdateExpression': 'SET bal = bal + :d',
                                'ExpressionAttributeValues': {':d': {'N': str(_AMOUNT)}}}},
                ])
                return None
            except ClientError as exc:
                code = exc.response['Error']['Code']
                if code != ERR_TRANSACTION_CANCELED:
                    return f'{src}->{dst}: {code}'
                reasons = [r.get('Code') for r in exc.response.get('CancellationReasons') or []]
                if 'ConditionalCheckFailed' in reasons:
                    return f'{src}->{dst}: balance went negative, reasons {reasons!r}'
                time.sleep(0.05 * (attempt + 1))
        return f'{src}->{dst}: still conflicting after 30 attempts'

    def _writer() -> list[str]:
        out = []
        for i in range(_MOVES):
            src, dst = ('A', 'B') if i % 2 == 0 else ('B', 'A')
            err = _move(src, dst)
            if err is not None:
                out.append(err)
        return out

    def _reader() -> list[tuple[int, int]]:
        pairs = []
        for _ in range(_READS):
            for attempt in range(30):
                try:
                    resp = ddb.transact_get_items(TransactItems=[
                        {'Get': {'TableName': table, 'Key': {'pk': {'S': 'A'}}}},
                        {'Get': {'TableName': table, 'Key': {'pk': {'S': 'B'}}}},
                    ])
                    pairs.append((int(resp['Responses'][0]['Item']['bal']['N']),
                                  int(resp['Responses'][1]['Item']['bal']['N'])))
                    break
                except ClientError as exc:
                    if exc.response['Error']['Code'] != ERR_TRANSACTION_CANCELED:
                        raise
                    time.sleep(0.05 * (attempt + 1))
        return pairs

    with ThreadPoolExecutor(max_workers=2) as pool:
        writer_future = pool.submit(_writer)
        reader_future = pool.submit(_reader)
        writer_errors = writer_future.result()
        observed = reader_future.result()

    torn = [p for p in observed if sum(p) != _TOTAL]
    assert torn == [], (
        f'a transactional read observed a torn transfer: {torn!r} out of {len(observed)!r} '
        f'observations did not sum to {_TOTAL!r}'
    )
    assert writer_errors == [], (
        f'the writer transactions failed for a reason other than contention: {writer_errors!r}'
    )
    assert len(observed) == _READS, (
        f'the reader did not complete its reads: {len(observed)!r} of {_READS!r}'
    )

    final = {n: int(ddb.get_item(TableName=table, Key={'pk': {'S': n}},
                                ConsistentRead=True)['Item']['bal']['N'])
             for n in ('A', 'B')}
    assert final['A'] + final['B'] == _TOTAL, (
        f'the final balances violate the conservation invariant: {final!r}'
    )
    # An even number of alternating moves must land the value back where it started, so a
    # half-applied final transfer is caught even if every intermediate read got lucky.
    assert final == {'A': _TOTAL // 2, 'B': _TOTAL // 2}, (
        f'{_MOVES!r} alternating transfers must return both balances to {_TOTAL // 2!r}, got '
        f'{final!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
