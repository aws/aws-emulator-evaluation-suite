"""conc-ddb-optimistic-put-race-winner-payload-intact."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-ddb-optimistic-put-race-winner-payload-intact"
GROUP = 'concurrency'
SERVICES = ['dynamodb']

ROUNDS = 4
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
    """Run every fn at the same instant (one Barrier); return ('ok', resp) / ('err', code) each."""
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
    """Eight writers racing a version-guarded full-item PutItem leave one winner per round, and the
    item holds exactly the winner's attributes: none from a loser or the previous round's winner.
    """
    ddb = ctx.client('dynamodb')
    table = _make_table(ctx)
    ddb.put_item(TableName=table, Item={
        'pk': {'S': 'doc'}, 'version': {'N': '0'}, 'writer': {'S': 'seed'}, 'only_seed': {'S': 'seed'},
    })

    def _put(expected, me):
        item = {
            'pk': {'S': 'doc'}, 'version': {'N': str(expected + 1)}, 'writer': {'S': me},
            f'only_{me}': {'S': me},
        }
        return lambda: ddb.put_item(
            TableName=table, Item=item,
            ConditionExpression='version = :expected',
            ExpressionAttributeValues={':expected': {'N': str(expected)}},
        )

    successes = 0
    for rnd in range(ROUNDS):
        expected = int(ddb.get_item(TableName=table, Key={'pk': {'S': 'doc'}},
                                    ConsistentRead=True)['Item']['version']['N'])
        assert expected == rnd, f'round {rnd}: version before the race is {expected!r}, expected {rnd}'
        ids = [f'r{rnd}w{i}' for i in range(RACERS)]
        outcomes = _race([_put(expected, me) for me in ids])

        won = [ids[i] for i, (kind, _) in enumerate(outcomes) if kind == 'ok']
        lost_codes = [val for kind, val in outcomes if kind == 'err']
        assert len(won) == 1, f'round {rnd}: winners {won!r}; exactly one conditional PutItem may win'
        assert lost_codes == [ERR_CCF] * (RACERS - 1), (
            f'round {rnd}: losers must each get {ERR_CCF}; got {lost_codes!r}'
        )
        successes += 1

        item = ddb.get_item(TableName=table, Key={'pk': {'S': 'doc'}}, ConsistentRead=True)['Item']
        assert set(item) == {'pk', 'version', 'writer', f'only_{won[0]}'}, (
            f'round {rnd}: item attributes {sorted(item)!r} must be exactly the winner {won[0]!r}\'s '
            f'payload -- anything else is a loser\'s or a stale attribute surviving'
        )
        assert item['writer'] == {'S': won[0]} and item['version'] == {'N': str(expected + 1)}, (
            f'round {rnd}: item {item!r} is not the winner {won[0]!r}\'s version {expected + 1}'
        )

    final = ddb.get_item(TableName=table, Key={'pk': {'S': 'doc'}}, ConsistentRead=True)['Item']
    assert int(final['version']['N']) == successes == ROUNDS, (
        f'final version {final["version"]!r}, {successes} successes, {ROUNDS} rounds'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
