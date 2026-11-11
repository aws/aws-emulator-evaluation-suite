"""conc-ddb-optimistic-transact-race-cancelled-leaves-no-partial-write."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-ddb-optimistic-transact-race-cancelled-leaves-no-partial-write"
GROUP = 'transactions'
SERVICES = ['dynamodb']

ROUNDS = 3
RACERS = 8
ERR_CANCELED = 'TransactionCanceledException'


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Eight TransactWriteItems racing on a version-guarded item commit at most once per round; each
    cancelled one has positional CancellationReasons (only the contended slot non-None) and leaves
    its private item unwritten. The version advances by exactly the number of commits.
    """
    ddb = ctx.client('dynamodb')
    table = _make_table(ctx)
    ddb.put_item(TableName=table, Item={'pk': {'S': 'shared'}, 'version': {'N': '0'}})

    def _tx(expected, private_pk):
        return lambda: ddb.transact_write_items(TransactItems=[
            {'Update': {
                'TableName': table, 'Key': {'pk': {'S': 'shared'}},
                'UpdateExpression': 'SET version = :next, last_tx = :me',
                'ConditionExpression': 'version = :expected',
                'ExpressionAttributeValues': {':expected': {'N': str(expected)},
                                              ':next': {'N': str(expected + 1)},
                                              ':me': {'S': private_pk}},
            }},
            {'Put': {'TableName': table, 'Item': {'pk': {'S': private_pk}},
                     'ConditionExpression': 'attribute_not_exists(pk)'}},
            {'ConditionCheck': {'TableName': table, 'Key': {'pk': {'S': f'anchor-{private_pk}'}},
                                'ConditionExpression': 'attribute_exists(pk)'}},
        ])

    def _exists(pk):
        return 'Item' in ddb.get_item(TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True)

    def _version():
        return int(ddb.get_item(TableName=table, Key={'pk': {'S': 'shared'}},
                                ConsistentRead=True)['Item']['version']['N'])

    # --- positive control: uncontended, the same shape commits every member ----------------------
    ddb.put_item(TableName=table, Item={'pk': {'S': 'anchor-private-control'}})
    ctl = _attempt(_tx(0, 'private-control'))
    assert ctl[0] == 'ok', f'uncontended control transaction failed: {ctl[1]!r} {ctl[2]!r}'
    assert _exists('private-control') and _version() == 1, (
        f'control commit did not land both writes: private={_exists("private-control")!r} '
        f'version={_version()!r}'
    )

    commits = 1
    seen_contended_codes = set()
    for rnd in range(ROUNDS):
        expected = _version()
        assert expected == commits, f'round {rnd}: version {expected!r} != commits so far {commits}'
        privs = [f'private-r{rnd}-t{i}' for i in range(RACERS)]
        # Per-racer anchors: a ConditionCheck on an item other in-flight transactions also check
        # is itself contended and can report TransactionConflict, so it could not be asserted None.
        for pk in privs:
            ddb.put_item(TableName=table, Item={'pk': {'S': f'anchor-{pk}'}})
        barrier = threading.Barrier(RACERS)

        def _racer(pk, _expected=expected):
            barrier.wait(timeout=60)
            return _attempt(_tx(_expected, pk))

        with ThreadPoolExecutor(max_workers=RACERS) as pool:
            outcomes = [f.result() for f in [pool.submit(_racer, pk) for pk in privs]]

        committed = [privs[i] for i, o in enumerate(outcomes) if o[0] == 'ok']
        assert len(committed) <= 1, (
            f'round {rnd}: {committed!r} all committed against version={expected}; at most one can'
        )
        for pk, o in zip(privs, outcomes):
            if o[0] == 'ok':
                assert _exists(pk), f'round {rnd}: committed transaction {pk!r} left no private item'
                continue
            assert o[1] == ERR_CANCELED, f'round {rnd}: {pk!r} failed with {o[1]!r}, not {ERR_CANCELED}'
            reasons = o[2].get('CancellationReasons')
            assert isinstance(reasons, list) and len(reasons) == 3, (
                f'round {rnd}: {pk!r} CancellationReasons {reasons!r} must be 3 entries, one per member'
            )
            codes = [r.get('Code') for r in reasons]
            assert codes[1] == 'None' and codes[2] == 'None', (
                f'round {rnd}: {pk!r} reasons {codes!r} -- its private Put and its own anchor '
                f'ConditionCheck were uncontended and must be positionally None'
            )
            assert codes[0] is not None and codes[0] != 'None', (
                f'round {rnd}: {pk!r} reasons {codes!r} -- the contended Update in slot 0 caused the '
                f'cancellation and must carry a code'
            )
            seen_contended_codes.add(codes[0])
            assert not _exists(pk), (
                f'round {rnd}: cancelled transaction {pk!r} left its private item behind -- partial write'
            )
        commits += len(committed)
        if committed:
            shared = ddb.get_item(TableName=table, Key={'pk': {'S': 'shared'}},
                                  ConsistentRead=True)['Item']
            assert shared['last_tx'] == {'S': committed[0]}, (
                f'round {rnd}: shared item names {shared["last_tx"]!r}, committed was {committed[0]!r}'
            )

    assert _version() == commits, (
        f'final version {_version()!r} != commits {commits} (contended codes seen: '
        f'{sorted(seen_contended_codes)!r})'
    )
    assert seen_contended_codes, 'no transaction was cancelled across the races -- no contention occurred'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
