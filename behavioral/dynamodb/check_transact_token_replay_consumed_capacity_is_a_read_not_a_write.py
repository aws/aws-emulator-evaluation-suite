"""transact-token-replay-consumed-capacity-is-a-read-not-a-write."""
from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "transact-token-replay-consumed-capacity-is-a-read-not-a-write"
GROUP = 'idempotency-retry'
SERVICES = ['dynamodb']
ERR_MISMATCH = 'IdempotentParameterMismatchException'
MSG_MISMATCH = ('Specified idempotent token was used with different request parameters within the '
                'idempotency window')
_RACERS = 24


@tags('axis:rejection', 'cap:c2', 'concern:data-plane', 'concern:negative-classes',
      'dp:api', 'plane:data')
def run(ctx) -> None:
    """A TransactWriteItems replay under the same ClientRequestToken bills READ capacity, 24
    concurrent first uses of one token collapse to one write (counter 1), a fresh token writes
    again, and a changed operand raises IdempotentParameterMismatchException without effect."""
    plain = ctx.client('dynamodb')
    # A 24-way barrier release through one cached client needs a connection pool wider than
    # botocore's default 10, or the race closes on the pool instead of on the service.
    racer_client = ctx.client('dynamodb', config=Config(max_pool_connections=64))
    table = ctx.unique_name('sim2real-behav-d3cc-')
    plain.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_if_present(plain, table))
    plain.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def item():
        return plain.get_item(
            TableName=table, Key={'pk': {'S': 'ctr'}}, ConsistentRead=True).get('Item')

    def counter():
        got = item()
        return None if got is None else got['n']['N']

    def transact(client, token, operand='1'):
        return client.transact_write_items(
            ClientRequestToken=token,
            ReturnConsumedCapacity='INDEXES',
            TransactItems=[{'Update': {
                'TableName': table,
                'Key': {'pk': {'S': 'ctr'}},
                'UpdateExpression': 'ADD n :one',
                'ExpressionAttributeValues': {':one': {'N': operand}},
            }}],
        )

    # --- 24 simultaneous FIRST uses of one token ---
    token = str(uuid.uuid4())
    barrier = threading.Barrier(_RACERS)

    def racer(_):
        barrier.wait()
        try:
            return ('ok', transact(racer_client, token)['ConsumedCapacity'])
        except ClientError as exc:
            return ('err', exc.response['Error']['Code'])

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        results = list(pool.map(racer, range(_RACERS)))

    errors = [payload for kind, payload in results if kind == 'err']
    assert not errors, (
        f'{len(errors)} of {_RACERS} concurrent first-uses of one ClientRequestToken failed with '
        f'{sorted(set(errors))!r}; a token race must collapse, not surface as an error'
    )
    capacities = [payload[0] for kind, payload in results if kind == 'ok']
    assert len(capacities) == _RACERS, (
        f'{len(capacities)} of {_RACERS} responses carried ConsumedCapacity; '
        f"ReturnConsumedCapacity='INDEXES' must be honoured on every one"
    )

    writers = [c for c in capacities if c.get('WriteCapacityUnits', 0) > 0]
    readers = [c for c in capacities if c.get('ReadCapacityUnits', 0) > 0]
    assert len(writers) == 1, (
        f'{len(writers)} of {_RACERS} concurrent calls reported WriteCapacityUnits > 0, expected '
        f'exactly 1 — the write units are how the service names which call actually committed'
    )
    assert len(readers) == _RACERS - 1, (
        f'{len(readers)} of {_RACERS} calls reported ReadCapacityUnits > 0, expected '
        f'{_RACERS - 1}; a deduplicated replay is served by READING the ledger'
    )
    assert all(r.get('WriteCapacityUnits', 0) == 0 for r in readers), (
        f'a replay reported both read and write units: '
        f'{[r for r in readers if r.get("WriteCapacityUnits", 0)][:1]!r}'
    )
    assert writers[0].get('ReadCapacityUnits', 0) == 0, (
        f'the single committing call reported ReadCapacityUnits too: {writers[0]!r}')
    total_write = sum(c.get('WriteCapacityUnits', 0) for c in capacities)
    assert total_write == writers[0]['WriteCapacityUnits'], (
        f'{_RACERS} calls billed {total_write!r} write capacity units in total but the one '
        f'committing call billed {writers[0]["WriteCapacityUnits"]!r}; the replays must cost no '
        f'write capacity at all'
    )
    assert writers[0]['Table']['WriteCapacityUnits'] == writers[0]['WriteCapacityUnits'], (
        f'table-level and aggregate write units disagree: {writers[0]!r}')
    assert readers[0]['Table']['ReadCapacityUnits'] == readers[0]['ReadCapacityUnits'], (
        f'table-level and aggregate read units disagree: {readers[0]!r}')

    # the effect count: a NON-idempotent ADD is the only thing that can tell dedup from re-execution
    assert counter() == '1', (
        f'{_RACERS} concurrent deliveries of one token left the counter at {counter()!r}, '
        f"expected '1' — two threads both seeing a ledger miss is exactly what an unlocked "
        f'setdefault produces'
    )

    # --- a sequential replay is a read as well ---
    # ReturnConsumedCapacity is part of the idempotency fingerprint, so it is left unchanged.
    replay = transact(plain, token)['ConsumedCapacity'][0]
    assert replay.get('ReadCapacityUnits', 0) > 0, (
        f'the sequential replay reported {replay!r}; a replay must bill read capacity')
    assert replay.get('WriteCapacityUnits', 0) == 0, (
        f'the sequential replay billed write capacity: {replay!r}')
    assert counter() == '1', f'the sequential replay moved the counter to {counter()!r}'

    # --- positive control: a fresh token is a write and applies the work again ---
    fresh = transact(plain, str(uuid.uuid4()))['ConsumedCapacity'][0]
    assert fresh.get('WriteCapacityUnits', 0) > 0, (
        f'a FRESH token reported {fresh!r}; an unseen token must bill write capacity')
    assert fresh.get('ReadCapacityUnits', 0) == 0, (
        f'a fresh token billed read capacity: {fresh!r}')
    assert counter() == '2', (
        f'a fresh token left the counter at {counter()!r}, expected \'2\' — dedup is scoped to the '
        f'token, and the table was writable throughout'
    )

    # --- NEGATIVE: the first token with one changed operand is rejected, and changes nothing ---
    try:
        transact(plain, token, operand='5')
        raise AssertionError(
            'replaying a used ClientRequestToken with a changed operand was accepted; real AWS '
            f'raises {ERR_MISMATCH}'
        )
    except ClientError as exc:
        code = exc.response['Error']['Code']
        assert code == ERR_MISMATCH, (
            f'a token replay with a changed operand raised {code!r}, expected {ERR_MISMATCH!r}')
        message = exc.response['Error'].get('Message')
        assert message == MSG_MISMATCH, (
            f'a token replay with a changed operand said {message!r}, expected {MSG_MISMATCH!r}')

    # effect-absent probe
    assert counter() == '2', (
        f'the rejected mismatch replay moved the counter to {counter()!r}; a refused call must '
        f'apply nothing'
    )
    assert set(item()) == {'pk', 'n'}, (
        f'the item carries attributes {sorted(item())!r}; the idempotency ledger must not leave '
        f'anything behind on the customer\'s item'
    )

    # --- cleanup verification ---
    plain.delete_table(TableName=table)
    plain.get_waiter('table_not_exists').wait(
        TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 100})
    try:
        plain.describe_table(TableName=table)
        raise AssertionError(f'{table} still describable after delete_table')
    except ClientError as exc:
        code = exc.response['Error']['Code']
        assert code == 'ResourceNotFoundException', (
            f'describe_table on the deleted table raised {code!r}, expected '
            f'ResourceNotFoundException')
        expected = f'Requested resource not found: Table: {table} not found'
        message = exc.response['Error'].get('Message')
        assert message == expected, (
            f'describe_table on the deleted table said {message!r}, expected {expected!r}')


def _delete_table_if_present(ddb, table):
    """Teardown for a table the check itself may already have deleted."""
    try:
        ddb.delete_table(TableName=table)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            raise


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
