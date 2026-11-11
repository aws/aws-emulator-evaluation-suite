"""conc-ddb-optimistic-delete-race-losers-see-no-item."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-ddb-optimistic-delete-race-losers-see-no-item"
GROUP = 'concurrency'
SERVICES = ['dynamodb']

RACERS = 8
ERR_CCF = 'ConditionalCheckFailedException'
CCF_MESSAGE = 'The conditional request failed'


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


def _attempt(fn):
    """('ok', response, None) or ('err', code, full error response). Non-ClientError propagates."""
    try:
        return ('ok', fn(), None)
    except ClientError as exc:
        return ('err', exc.response.get('Error', {}).get('Code'), exc.response)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Eight racers on a version-guarded DeleteItem yield one deleter handed the whole item; each
    loser gets ConditionalCheckFailedException with no ALL_OLD Item, because the item no longer
    exists. Control: a stale version on a live item is refused with the item attached.
    """
    ddb = ctx.client('dynamodb')
    table = _make_table(ctx)
    key = {'pk': {'S': 'lease'}}
    seeded = {'pk': {'S': 'lease'}, 'version': {'N': '3'}, 'holder': {'S': 'seed'}}

    def _delete(expected):
        return lambda: ddb.delete_item(
            TableName=table, Key=key,
            ConditionExpression='version = :expected',
            ExpressionAttributeValues={':expected': {'N': str(expected)}},
            ReturnValues='ALL_OLD', ReturnValuesOnConditionCheckFailure='ALL_OLD',
        )

    def _get():
        return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')

    # --- control: stale version against a LIVE item is refused with the item attached ----------
    ddb.put_item(TableName=table, Item=seeded)
    ctl = _attempt(_delete(2))
    assert ctl[0] == 'err' and ctl[1] == ERR_CCF, f'stale delete on a live item: {ctl[:2]!r}'
    assert ctl[2]['Error'].get('Message') == CCF_MESSAGE, f'stale delete message: {ctl[2]["Error"]!r}'
    assert ctl[2].get('Item') == seeded, (
        f'a CCF against a live item must carry it under ALL_OLD; got {ctl[2].get("Item")!r}'
    )
    assert _get() == seeded, f'a refused delete removed or changed the item: {_get()!r}'

    # --- the race: everyone holds the right version ---------------------------------------------
    barrier = threading.Barrier(RACERS)

    def _racer(_i):
        barrier.wait(timeout=60)
        return _attempt(_delete(3))

    with ThreadPoolExecutor(max_workers=RACERS) as pool:
        outcomes = [f.result() for f in [pool.submit(_racer, i) for i in range(RACERS)]]

    wins = [o for o in outcomes if o[0] == 'ok']
    losses = [o for o in outcomes if o[0] == 'err']
    assert len(wins) == 1, f'{len(wins)} callers were told they deleted the item; exactly one may'
    assert wins[0][1].get('Attributes') == seeded, (
        f'the deleter was handed {wins[0][1].get("Attributes")!r}, not the item it deleted {seeded!r}'
    )
    assert [o[1] for o in losses] == [ERR_CCF] * (RACERS - 1), (
        f'losers must each get {ERR_CCF}; got {[o[1] for o in losses]!r}'
    )
    assert [o[2]['Error'].get('Message') for o in losses] == [CCF_MESSAGE] * (RACERS - 1), (
        f'losers must each get the message {CCF_MESSAGE!r}; got {[o[2]["Error"] for o in losses]!r}'
    )
    ghosts = [o[2].get('Item') for o in losses if 'Item' in o[2]]
    assert ghosts == [], (
        f'{len(ghosts)} losers were handed an ALL_OLD image of an item that was already deleted: '
        f'{ghosts[:2]!r}'
    )
    assert _get() is None, f'item survived the winning delete: {_get()!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
