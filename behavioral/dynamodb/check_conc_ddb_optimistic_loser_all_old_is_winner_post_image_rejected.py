"""conc-ddb-optimistic-loser-all-old-is-winner-post-image-rejected."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-ddb-optimistic-loser-all-old-is-winner-post-image-rejected"
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
    """('ok', response) or ('err', code, full error response). Non-ClientError propagates."""
    try:
        return ('ok', fn(), None)
    except ClientError as exc:
        return ('err', exc.response.get('Error', {}).get('Code'), exc.response)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Each loser of an eight-way version race gets ConditionalCheckFailedException whose ALL_OLD
    Item is the winner's post-image, and can retry from it alone; without the parameter a refusal
    carries no Item, and refusals never change the item.
    """
    ddb = ctx.client('dynamodb')
    table = _make_table(ctx)
    key = {'pk': {'S': 'cart'}}
    ddb.put_item(TableName=table, Item={'pk': {'S': 'cart'}, 'version': {'N': '0'},
                                        'writer': {'S': 'seed'}})

    def _update(expected, me, *, all_old=True, return_new=False):
        kwargs = dict(
            TableName=table, Key=key,
            UpdateExpression='SET version = :next, writer = :me',
            ConditionExpression='version = :expected',
            ExpressionAttributeValues={':expected': {'N': str(expected)},
                                       ':next': {'N': str(expected + 1)}, ':me': {'S': me}},
        )
        if all_old:
            kwargs['ReturnValuesOnConditionCheckFailure'] = 'ALL_OLD'
        if return_new:
            kwargs['ReturnValues'] = 'ALL_NEW'
        return lambda: ddb.update_item(**kwargs)

    # --- the race: everyone read version 0 -----------------------------------------------------
    ids = [f'w{i}' for i in range(RACERS)]
    barrier = threading.Barrier(RACERS)

    def _racer(me):
        barrier.wait(timeout=60)
        return _attempt(_update(0, me, return_new=True))

    with ThreadPoolExecutor(max_workers=RACERS) as pool:
        outcomes = [f.result() for f in [pool.submit(_racer, me) for me in ids]]

    winners = [(ids[i], o[1]) for i, o in enumerate(outcomes) if o[0] == 'ok']
    losers = [(ids[i], o) for i, o in enumerate(outcomes) if o[0] == 'err']
    assert len(winners) == 1, f'{len(winners)} winners {[w for w, _ in winners]!r}; exactly one may win'
    winner_id, winner_resp = winners[0]
    post_image = winner_resp['Attributes']
    assert post_image == {'pk': {'S': 'cart'}, 'version': {'N': '1'}, 'writer': {'S': winner_id}}, (
        f'winner ALL_NEW {post_image!r} is not version 1 written by {winner_id!r}'
    )
    assert [o[1] for _, o in losers] == [ERR_CCF] * (RACERS - 1), (
        f'losers must each get {ERR_CCF}; got {[o[1] for _, o in losers]!r}'
    )
    assert [o[2]['Error'].get('Message') for _, o in losers] == [CCF_MESSAGE] * (RACERS - 1), (
        f'losers must each get the message {CCF_MESSAGE!r}; got {[o[2]["Error"] for _, o in losers]!r}'
    )
    for me, o in losers:
        assert o[2].get('Item') == post_image, (
            f'loser {me!r} ALL_OLD Item {o[2].get("Item")!r} is not the winner\'s post-image '
            f'{post_image!r} -- the recovery payload must be the state that beat it'
        )

    # --- effect absent: no parameter, no Item; and neither refusal changed anything -------------
    bare = _attempt(_update(0, 'stale-no-param', all_old=False))
    assert bare[0] == 'err' and bare[1] == ERR_CCF, f'stale write without ALL_OLD: {bare[:2]!r}'
    assert bare[2]['Error'].get('Message') == CCF_MESSAGE, f'stale write message: {bare[2]["Error"]!r}'
    assert 'Item' not in bare[2], (
        f'a CCF without ReturnValuesOnConditionCheckFailure must carry no Item; got {bare[2].get("Item")!r}'
    )
    now = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
    assert now == post_image, f'refused writes changed the item: {now!r} != {post_image!r}'

    # --- recovery: each loser retries from the image it holds, never reading ---------------------
    for me, o in losers:
        held = o[2]['Item']
        landed = False
        for _attempt_no in range(2):  # a stale image costs exactly one more refusal, never more
            res = _attempt(_update(int(held['version']['N']), me))
            if res[0] == 'ok':
                landed = True
                break
            assert res[1] == ERR_CCF, f'loser {me!r} retry got {res[1]!r}, expected {ERR_CCF}'
            held = res[2].get('Item')
            assert held is not None, f'loser {me!r} retry CCF carried no ALL_OLD Item: {res[2]!r}'
        assert landed, f'loser {me!r} could not land from its ALL_OLD image within 2 attempts'

    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
    assert final['version'] == {'N': str(RACERS)}, (
        f'final version {final["version"]!r}; 1 winner + {len(losers)} recovered losers = {RACERS}'
    )
    assert final['writer'] == {'S': losers[-1][0]}, (
        f'final writer {final["writer"]!r}, expected the last loser to recover {losers[-1][0]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
