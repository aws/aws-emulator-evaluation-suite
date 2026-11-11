"""deep-dynamodb-1-ddbvec-update-table-backfills-preexisting-items."""
from __future__ import annotations

import math
import time

from behavioral_harness import tags

CHECK = "deep-dynamodb-1-ddbvec-update-table-backfills-preexisting-items"
GROUP = 'vector'
SERVICES = ['dynamodb']

_N_PREEXISTING = 30
_QUERY = [0.0, 0.0, 0.0, 0.0]
# On AWS, Backfilling turns true about 30 s after UpdateTable and the index reaches ACTIVE about
# 510 s after it, for 30 items. The ceiling is generous on purpose.
_BACKFILL_BUDGET_S = 1500
#: Index additions tried before the check gives up on observing the CREATING and Backfilling windows.
_ATTEMPTS = 3
#: Seconds after UpdateTable during which the state is read at a short interval.
_FAST_POLL_S = 30


def _vec_for(i):
    # Distinct euclidean distances from the origin, so the nearest-first order is a total order.
    return [1.0 + i, 0.5 * (i % 3), 0.25, 0.0]


def _euclid(u, v):
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(u, v)))


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A vector index added by UpdateTable refuses searches while CREATING, passes CREATING with Backfilling true to
    ACTIVE, and then returns all 30 pre-existing items plus one written mid-backfill, nearest-first.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvec-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    # DeleteTable is refused (ResourceInUseException) while a vector index is CREATING, so a
    # plain delete registered here would leak the table whenever the check fails mid-backfill.
    ctx.on_cleanup(lambda: _delete_table_when_settled(ddb, table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    assert not ddb.describe_table(TableName=table)['Table'].get('VectorIndexes'), (
        'a table created without VectorIndexes already reports one'
    )

    vectors = {f'item-{i:02d}': _vec_for(i) for i in range(_N_PREEXISTING)}
    for pk, vec in vectors.items():
        ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'emb': {'L': _vec(vec)},
                                            'payload': {'S': f'p-{pk}'}})
    scanned = ddb.scan(TableName=table, Select='COUNT', ConsistentRead=True)['Count']
    assert scanned == _N_PREEXISTING, f'expected {_N_PREEXISTING} items before the index, got {scanned}'

    # Each attempt adds the index and watches it to ACTIVE. An attempt that misses the CREATING
    # refusal or the Backfilling window drops the index and adds it again, up to _ATTEMPTS times,
    # while the budget left holds a full attempt (the longest add-to-ACTIVE seen so far).
    refused = False
    tried = []
    took = []
    states = []
    mid_written = False
    final = {}
    budget_s = _bound(ctx, _BACKFILL_BUDGET_S)
    deadline = time.time() + budget_s
    for attempt in range(_ATTEMPTS):
        if attempt:
            _drop_index(ddb, table, deadline)
            left = deadline - time.time()
            assert left >= max(took), (
                f'the CREATING refusal and the Backfilling window were never both observed in '
                f'{attempt} attempts; {left:.0f}s left cannot hold another ({max(took):.0f}s to '
                f'ACTIVE): {tried!r}'
            )
        _add_index(ddb, table)
        armed = time.time()
        if not refused:
            # The model: "The index must be in the ACTIVE state." A CREATING index is not searchable.
            err = _outcome(lambda: ddb.search_vectors(TableName=table, IndexName='late-euc', TopK=5,
                                                      SearchVector=_vec(_QUERY)))
            if err == ('ValidationException', 'The table does not have the specified index: late-euc'):
                refused = True
            else:
                now = _index(ddb, table).get('IndexStatus')
                assert now != 'CREATING', (
                    f'searching a vector index that stayed CREATING answered {err!r}; expected '
                    f"ValidationException 'The table does not have the specified index: late-euc'"
                )
                tried.append(f'search answered {err!r} with the index already {now!r}')

        # Poll to completion, recording every distinct (IndexStatus, Backfilling) state seen.
        states = []
        mid_written = False
        final = {}
        while time.time() < deadline:
            tbl = ddb.describe_table(TableName=table)['Table']
            cur = [v for v in tbl.get('VectorIndexes') or [] if v.get('IndexName') == 'late-euc']
            assert cur, f'the vector index vanished while being created: {tbl.get("VectorIndexes")!r}'
            final = cur[0]
            state = (final.get('IndexStatus'), bool(final.get('Backfilling')))
            if not states or states[-1] != state:
                states.append(state)
            if state == ('CREATING', True) and not mid_written:
                ddb.put_item(TableName=table, Item={'pk': {'S': 'mid-backfill'},
                                                    'emb': {'L': _vec([0.5, 0.0, 0.0, 0.0])},
                                                    'payload': {'S': 'p-mid-backfill'}})
                mid_written = True
            if state[0] == 'ACTIVE' and not state[1] and tbl['TableStatus'] == 'ACTIVE':
                break
            time.sleep(0.2 if time.time() - armed < _FAST_POLL_S else 1)
        assert final.get('IndexStatus') == 'ACTIVE', (
            f'the vector index never became ACTIVE within {budget_s:.0f}s; states seen {states!r}'
        )
        if refused and mid_written:
            break
        tried.append(f'attempt {attempt + 1} states {states!r}')
        took.append(time.time() - armed)
    assert refused, f'SearchVectors was never refused while the index was CREATING: {tried!r}'
    assert ('CREATING', True) in states, (
        f'a vector index created over {_N_PREEXISTING} existing items never reported '
        f'Backfilling=true in {_ATTEMPTS} attempts: {tried!r}'
    )
    assert states[-1] == ('ACTIVE', False), f'backfill did not end ACTIVE/not-backfilling: {states!r}'
    assert states.index(('CREATING', True)) < states.index(('ACTIVE', False)), (
        f'Backfilling=true must precede ACTIVE: {states!r}'
    )
    assert mid_written, f'no write landed during the backfill window; states {states!r}'
    for field in ('ItemCount', 'IndexSizeBytes'):
        val = final.get(field)
        assert isinstance(val, int) and val >= 0, f'{field} on the ACTIVE index was {val!r}'

    expected = sorted(list(vectors) + ['mid-backfill'],
                      key=lambda pk: _euclid(_QUERY, vectors.get(pk, [0.5, 0.0, 0.0, 0.0])))
    res = []
    search_deadline = time.time() + 120
    while time.time() < search_deadline:
        res = ddb.search_vectors(TableName=table, IndexName='late-euc', TopK=100,
                                 SearchVector=_vec(_QUERY))['SearchResults']
        if len(res) >= len(expected):
            break
        time.sleep(2)
    got = [r['Item']['pk']['S'] for r in res]
    missing = sorted(set(expected) - set(got))
    assert not missing, (
        f'{len(missing)} items were never backfilled into the new index: {missing!r} '
        f'(returned {len(got)})'
    )
    assert got == expected, f'backfilled index order {got!r} is not nearest-first {expected!r}'
    for r in res:
        pk = r['Item']['pk']['S']
        assert r['Item'].get('payload') == {'S': f'p-{pk}'}, (
            f'backfilled item {pk!r} lost its projected payload: {r["Item"]!r}'
        )


def _add_index(ddb, table):
    resp = ddb.update_table(TableName=table, VectorIndexUpdates=[{'Create': {
        'IndexName': 'late-euc',
        'VectorAttribute': {'AttributeName': 'emb'},
        'Dimensions': 4,
        'DistanceFunction': 'EUCLIDEAN',
        'Projection': {'ProjectionType': 'ALL'},
    }}])
    vis = resp['TableDescription'].get('VectorIndexes') or []
    assert [v.get('IndexName') for v in vis] == ['late-euc'], f'UpdateTable described {vis!r}'
    assert vis[0].get('IndexStatus') == 'CREATING', (
        f'a just-requested vector index must be CREATING, was {vis[0].get("IndexStatus")!r}'
    )
    assert vis[0].get('Dimensions') == 4 and vis[0].get('DistanceFunction') == 'EUCLIDEAN', (
        f'UpdateTable echoed {vis[0]!r}'
    )


def _index(ddb, table):
    tbl = ddb.describe_table(TableName=table)['Table']
    cur = [v for v in tbl.get('VectorIndexes') or [] if v.get('IndexName') == 'late-euc']
    return cur[0] if cur else {}


def _drop_index(ddb, table, deadline):
    """Delete the vector index and wait until the table no longer lists it and is ACTIVE."""
    ddb.update_table(TableName=table, VectorIndexUpdates=[{'Delete': {'IndexName': 'late-euc'}}])
    while True:
        tbl = ddb.describe_table(TableName=table)['Table']
        names = [v.get('IndexName') for v in tbl.get('VectorIndexes') or []]
        if 'late-euc' not in names and tbl['TableStatus'] == 'ACTIVE':
            return
        if time.time() >= deadline:
            raise AssertionError(f'the dropped vector index is still listed: {tbl.get("VectorIndexes")!r}')
        time.sleep(1)


def _outcome(call):
    """(code, message) of the service error ``call`` raises, or ('<accepted>', repr of the answer)
    when the target accepts the call."""
    try:
        result = call()
    except Exception as exc:  # noqa: BLE001 -- the code IS the assertion
        err = (getattr(exc, 'response', None) or {}).get('Error')
        if not err:
            raise AssertionError(f'raised a non-service error {exc!r}') from exc
        return err.get('Code'), err.get('Message')
    return '<accepted>', repr(result)


def _bound(ctx, cap_s):
    """cap_s, bounded by the runner's remaining time less a reserve (a quarter, at most 150 s) for
    the search and teardown."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - min(150.0, left / 4)))


def _delete_table_when_settled(ddb, table, timeout_s=1500):
    deadline = time.time() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table)
            return
        except Exception as exc:  # noqa: BLE001
            code = (getattr(exc, 'response', None) or {}).get('Error', {}).get('Code')
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException' or time.time() > deadline:
                raise
        time.sleep(5)

def _vec(values):
    return [{'N': repr(float(x))} for x in values]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
