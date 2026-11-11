"""vector-write-request-bytes-floor-and-per-dimension-cost."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "vector-write-request-bytes-floor-and-per-dimension-cost"
GROUP = 'vector'
SERVICES = ['dynamodb']

_SMALL_DIMENSIONS = 4
_LARGE_DIMENSIONS = 4096


def _vec(n):
    return [{'N': '0.5'} for _ in range(n)]


def _budget_s(ctx, cap_s):
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_vector_table_active(ctx, ddb, table, n_indexes, cap_s=240.0):
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    tbl = ddb.describe_table(TableName=table)['Table']
    while True:
        tbl = ddb.describe_table(TableName=table)['Table']
        indexes = tbl.get('VectorIndexes', [])
        if (tbl['TableStatus'] == 'ACTIVE' and len(indexes) == n_indexes
                and all(v.get('IndexStatus') == 'ACTIVE' for v in indexes)):
            return tbl
        if time.monotonic() >= deadline:
            raise AssertionError(
                f'table/vector indexes never became ACTIVE in time: status '
                f'{tbl["TableStatus"]!r}, indexes '
                f'{[(v.get("IndexName"), v.get("IndexStatus")) for v in indexes]!r}'
            )
        time.sleep(2)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A vector write's per-index VectorWriteRequestBytes is exact, not just positive: a vector at
    or below the floor bills the floor, and one past it bills dimensions*4 plus fixed overhead.
    A later write that changes only one of the two vector attributes meters only that index.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvecbytes-')

    def _vi(name, attr, dims):
        return {'IndexName': name, 'VectorAttribute': {'AttributeName': attr}, 'Dimensions': dims,
                'DistanceFunction': 'COSINE', 'Projection': {'ProjectionType': 'KEYS_ONLY'}}

    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[
            _vi('idx-small', 'emb_small', _SMALL_DIMENSIONS),
            _vi('idx-large', 'emb_large', _LARGE_DIMENSIONS),
        ],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_vector_table_active(ctx, ddb, table, 2)

    item = {
        'pk': {'S': 'v1'},
        'emb_small': {'L': _vec(_SMALL_DIMENSIONS)},
        'emb_large': {'L': _vec(_LARGE_DIMENSIONS)},
    }

    def _put(write_item):
        out = ddb.put_item(TableName=table, Item=write_item, ReturnConsumedCapacity='INDEXES')
        return out['ConsumedCapacity']

    first = _put(item)
    per_index = first.get('VectorIndexes') or {}
    small_bytes = per_index.get('idx-small', {}).get('VectorWriteRequestBytes')
    large_bytes = per_index.get('idx-large', {}).get('VectorWriteRequestBytes')
    table_wcu = first.get('Table', {}).get('CapacityUnits')

    assert small_bytes == 1024.0, (
        f'a {_SMALL_DIMENSIONS}-dimension write is below the per-write floor; '
        f'VectorWriteRequestBytes was {small_bytes!r}, expected the 1024-byte floor'
    )
    assert large_bytes == 16397.0, (
        f'a {_LARGE_DIMENSIONS}-dimension write; VectorWriteRequestBytes was {large_bytes!r}, '
        f'expected 16397.0'
    )
    assert table_wcu == 17.0, f'table WCU for this write was {table_wcu!r}, expected 17.0'

    # A later write that changes only the small vector's value re-meters only idx-small: the
    # large vector attribute is unchanged, so it is untouched by this write.
    changed_item = dict(item)
    changed_item['emb_small'] = {'L': [{'N': '0.75'} for _ in range(_SMALL_DIMENSIONS)]}
    second = _put(changed_item)
    second_per_index = second.get('VectorIndexes') or {}
    assert second_per_index.get('idx-small', {}).get('VectorWriteRequestBytes') == 1024.0, (
        f'the changed small vector was not metered against idx-small: {second_per_index!r}'
    )
    assert 'idx-large' not in second_per_index, (
        f"the large vector's value did not change, but idx-large was metered anyway: "
        f'{second_per_index!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
