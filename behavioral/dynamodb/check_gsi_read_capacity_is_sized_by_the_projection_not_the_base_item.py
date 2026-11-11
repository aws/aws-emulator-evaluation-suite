"""gsi-read-capacity-is-sized-by-the-projection-not-the-base-item."""
from __future__ import annotations

import math
import time

# Capacity rule: Query/Scan sums the RAW bytes of every item examined, rounds the TOTAL to the 4 KB
# boundary once (not per item), then halves for the eventually consistent GSI read.
#   H1  A Query served by a KEYS_ONLY GSI bills on the size of the INDEX entries (a few tens of
#       bytes each), not on the base items: exactly _KEYS_ONLY_EXPECTED units for this check's data.
#   H2  A Query served by an ALL-projection GSI over the same 40 ~4 KB items bills exactly
#       _ALL_EXPECTED units.
#   H3  ReturnConsumedCapacity=INDEXES on an index-served Query charges the index and reports
#       Table.CapacityUnits == 0.
#   H4  A GSI Query cannot be strongly consistent, so both numbers are eventual-read numbers and the
#       0.5 factor applies to BOTH sides equally.
#   H5  The KEYS_ONLY result items contain exactly {pk, gsi1pk} and nothing else.

from behavioral_harness import tags

CHECK = "gsi-read-capacity-is-sized-by-the-projection-not-the-base-item"
GROUP = 'gsi'
SERVICES = ['dynamodb']

_ITEMS = 40
_PARTITION = 'BUCKET#1'
_PAYLOAD = 'q' * 3800            # each base item ≈4 KB -> one read unit
_KEYS_ONLY_INDEX = 'idx-keys-only'
_ALL_INDEX = 'idx-all'

_PK_VALUES = [f'ITEM#{i:03d}' for i in range(_ITEMS)]
assert len({len(v) for v in _PK_VALUES}) == 1, (
    'this check predicts capacity to the exact byte, so every pk value must be the same length'
)
_PK_BYTES = len(_PK_VALUES[0])


def _rcu(total_item_bytes):
    """DynamoDB Query/Scan capacity: sum the bytes of every item examined, round the TOTAL up to
    the 4 KB boundary once (not per item), then halve for an eventually consistent read -- a GSI
    Query is always eventually consistent."""
    return math.ceil(total_item_bytes / 4096) / 2


# DynamoDB automatically projects the base table's key and the index key into every GSI entry
# regardless of ProjectionType, so a KEYS_ONLY entry holds exactly {pk, gsi1pk}.
_KEYS_ONLY_ITEM_BYTES = (len('pk') + _PK_BYTES) + (len('gsi1pk') + len(_PARTITION))
_ALL_ITEM_BYTES = _KEYS_ONLY_ITEM_BYTES + (len('payload') + len(_PAYLOAD))

_KEYS_ONLY_EXPECTED = _rcu(_ITEMS * _KEYS_ONLY_ITEM_BYTES)
_ALL_EXPECTED = _rcu(_ITEMS * _ALL_ITEM_BYTES)


def _drain_batch(ddb, table, requests, *, attempts=30):
    pending = {table: list(requests)}
    for _ in range(attempts):
        if not pending:
            return
        pending = ddb.batch_write_item(RequestItems=pending).get('UnprocessedItems') or {}
    raise AssertionError(f'BatchWriteItem never drained UnprocessedItems: {pending!r}')


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _query_index_settled(ctx, ddb, table, index, want, cap_s=30.0):
    """_query_index until the eventually consistent GSI holds `want` entries or cap_s ends; a stop
    forced by the runner's budget, short of cap_s, is no verdict."""
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    deadline = start + budget_s
    while True:
        result = _query_index(ddb, table, index)
        if len(result[0]) >= want:
            return result
        if time.monotonic() >= deadline:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{cap_s}s wait ended ({len(result[0])} of {want} entries on {index!r}); not graded"
                )
            return result
        time.sleep(1.0)


def _query_index(ddb, table, index):
    """One index Query, hard-failing if it paginates -- a partial page would halve the capacity."""
    resp = ddb.query(
        TableName=table,
        IndexName=index,
        KeyConditionExpression='gsi1pk = :g',
        ExpressionAttributeValues={':g': {'S': _PARTITION}},
        ReturnConsumedCapacity='INDEXES',
    )
    assert 'LastEvaluatedKey' not in resp, (
        f'this check compares single-page capacity, so the Query on {index!r} must not paginate at '
        f'this size; it returned LastEvaluatedKey {resp.get("LastEvaluatedKey")!r}'
    )
    consumed = resp['ConsumedCapacity']
    charged = consumed['GlobalSecondaryIndexes'][index]['CapacityUnits']
    return resp['Items'], charged, consumed


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Once both GSIs hold all 40 items, a KEYS_ONLY index Query bills exactly the size of its
    index entries and an ALL-projection Query over the same items bills exactly the size of the
    full items, both charged to the index and not the base table."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-gsisize-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'gsi1pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        GlobalSecondaryIndexes=[
            {'IndexName': _KEYS_ONLY_INDEX,
             'KeySchema': [{'AttributeName': 'gsi1pk', 'KeyType': 'HASH'}],
             'Projection': {'ProjectionType': 'KEYS_ONLY'}},
            {'IndexName': _ALL_INDEX,
             'KeySchema': [{'AttributeName': 'gsi1pk', 'KeyType': 'HASH'}],
             'Projection': {'ProjectionType': 'ALL'}},
        ],
        Tags=[{'Key': 'sim2real:managed', 'Value': 'true'},
              {'Key': 'sim2real:check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    expected_keys = sorted(f'ITEM#{i:03d}' for i in range(_ITEMS))
    for offset in range(0, _ITEMS, 25):
        _drain_batch(ddb, table, [
            {'PutRequest': {'Item': {
                'pk': {'S': pk},
                'gsi1pk': {'S': _PARTITION},
                'payload': {'S': _PAYLOAD},
            }}}
            for pk in expected_keys[offset:offset + 25]
        ])

    keys_only_items, keys_only_cap, keys_only_consumed = _query_index_settled(
        ctx, ddb, table, _KEYS_ONLY_INDEX, _ITEMS)
    all_items, all_cap, all_consumed = _query_index_settled(ctx, ddb, table, _ALL_INDEX, _ITEMS)

    # Both indexes must really have answered for all 40 items, or the numbers measure less work.
    assert sorted(i['pk']['S'] for i in keys_only_items) == expected_keys, (
        f'the KEYS_ONLY index must return all {_ITEMS!r} entries for {_PARTITION!r}; it returned '
        f'{len(keys_only_items)!r}, missing '
        f'{sorted(set(expected_keys) - {i["pk"]["S"] for i in keys_only_items})[:10]!r}'
    )
    assert sorted(i['pk']['S'] for i in all_items) == expected_keys, (
        f'the ALL index must return all {_ITEMS!r} entries for {_PARTITION!r}; it returned '
        f'{len(all_items)!r}'
    )

    # The projection really is a projection.
    keys_only_members = sorted({m for i in keys_only_items for m in i})
    assert keys_only_members == ['gsi1pk', 'pk'], (
        f'a KEYS_ONLY index entry holds the base key and the index key and nothing else, so the '
        f'result items must have members [\'gsi1pk\', \'pk\'], got {keys_only_members!r}'
    )
    all_members = sorted({m for i in all_items for m in i})
    assert all_members == ['gsi1pk', 'payload', 'pk'], (
        f'an ALL-projection index entry holds every base attribute, so the result items must have '
        f'members [\'gsi1pk\', \'payload\', \'pk\'], got {all_members!r}'
    )

    # The charge lands on the index, not the base table -- the premise of the comparison.
    for index, consumed in ((_KEYS_ONLY_INDEX, keys_only_consumed),
                            (_ALL_INDEX, all_consumed)):
        assert consumed.get('Table', {}).get('CapacityUnits', -1) == 0, (
            f'a Query served BY {index!r} must charge the index and not the base table, got '
            f'Table {consumed.get("Table")!r}'
        )

    assert keys_only_cap > 0, (
        f'the KEYS_ONLY Query read {_ITEMS!r} entries and must bill something, got '
        f'{keys_only_cap!r} -- with a zero baseline the comparison below is vacuous'
    )
    assert keys_only_cap == _KEYS_ONLY_EXPECTED, (
        f'{_ITEMS!r} KEYS_ONLY index entries totalling {_ITEMS * _KEYS_ONLY_ITEM_BYTES!r} raw bytes '
        f'must bill exactly {_KEYS_ONLY_EXPECTED!r} read units (ceil(bytes/4096)/2 for an eventually '
        f'consistent GSI read); it billed {keys_only_cap!r} -- a target that resolves the index by '
        f'fetching the ~4 KB BASE items would bill far more than this'
    )
    assert all_cap == _ALL_EXPECTED, (
        f'{_ITEMS!r} ALL-projection index entries totalling {_ITEMS * _ALL_ITEM_BYTES!r} raw bytes '
        f'must bill exactly {_ALL_EXPECTED!r} read units (ceil(bytes/4096)/2 for an eventually '
        f'consistent GSI read); it billed {all_cap!r}'
    )
    assert all_cap > keys_only_cap, (
        f'two indexes on the same key over the same {_ITEMS!r} items must cost differently because '
        f'they store different bytes: KEYS_ONLY {keys_only_cap!r} vs ALL {all_cap!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
