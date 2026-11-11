"""conc-ddb-optimistic-version-race-one-winner-per-round."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-ddb-optimistic-version-race-one-winner-per-round"
GROUP = 'concurrency'
SERVICES = ['dynamodb']

ROUNDS = 5
RACERS = 8
ERR_CCF = 'ConditionalCheckFailedException'


def _make_table(ctx):
    ddb = ctx.client('dynamodb')
    name = ctx.unique_name('sim2real-conc-ddb-opt-')
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _race(fns):
    """Run every fn at once behind one Barrier; return ('ok', response) or ('err', code) per fn.
    A non-ClientError propagates, so a harness failure is never counted as a losing racer.
    """
    barrier = threading.Barrier(len(fns))

    def _one(fn):
        barrier.wait(timeout=60)
        try:
            return ('ok', fn())
        except ClientError as exc:
            return ('err', exc.response.get('Error', {}).get('Code'))

    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        return [f.result() for f in [pool.submit(_one, fn) for fn in fns]]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Eight writers racing a version-guarded UpdateItem yield one winner per round, each loser gets
    ConditionalCheckFailedException, and after five rounds the version and history match exactly
    the winners, in order: no lost update and no phantom increment.
    """
    ddb = ctx.client('dynamodb')
    table = _make_table(ctx)
    key = {'pk': {'S': 'account'}}
    ddb.put_item(TableName=table, Item={
        'pk': {'S': 'account'}, 'version': {'N': '0'}, 'writer': {'S': 'seed'},
        'history': {'L': []},
    })

    def _bump(expected, me):
        return lambda: ddb.update_item(
            TableName=table, Key=key,
            UpdateExpression='SET version = :next, writer = :me, history = list_append(history, :me_l)',
            ConditionExpression='version = :expected',
            ExpressionAttributeValues={
                ':expected': {'N': str(expected)}, ':next': {'N': str(expected + 1)},
                ':me': {'S': me}, ':me_l': {'L': [{'S': me}]},
            },
        )

    winners = []
    for rnd in range(ROUNDS):
        before = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
        expected = int(before['version']['N'])
        assert expected == rnd, f'round {rnd}: version before the race is {expected!r}, expected {rnd}'
        ids = [f'r{rnd}-w{i}' for i in range(RACERS)]
        outcomes = _race([_bump(expected, me) for me in ids])

        won = [ids[i] for i, (kind, _) in enumerate(outcomes) if kind == 'ok']
        lost_codes = [val for kind, val in outcomes if kind == 'err']
        assert len(won) == 1, (
            f'round {rnd}: {len(won)} writers were told they won a version={expected} '
            f'compare-and-set (winners={won!r}); exactly one may win'
        )
        assert lost_codes == [ERR_CCF] * (RACERS - 1), (
            f'round {rnd}: losers must each get {ERR_CCF}; got {lost_codes!r}'
        )

        after = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
        assert after['version'] == {'N': str(expected + 1)}, (
            f'round {rnd}: version after one winning write is {after["version"]!r}, '
            f'expected {expected + 1}'
        )
        assert after['writer'] == {'S': won[0]}, (
            f'round {rnd}: item names writer {after["writer"]!r} but the caller told it won '
            f'was {won[0]!r} -- a loser\'s write landed'
        )
        winners.append(won[0])

    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
    assert int(final['version']['N']) == len(winners) == ROUNDS, (
        f'final version {final["version"]!r} vs {len(winners)} reported successes over {ROUNDS} rounds'
    )
    history = [e['S'] for e in final['history']['L']]
    assert history == winners, (
        f'history {history!r} must equal exactly the reported winners {winners!r} -- '
        f'an extra entry is a phantom increment, a missing one is a lost update'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
