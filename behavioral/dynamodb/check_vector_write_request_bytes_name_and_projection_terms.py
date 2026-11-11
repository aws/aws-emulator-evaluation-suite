"""vector-write-request-bytes-name-and-projection-terms."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "vector-write-request-bytes-name-and-projection-terms"
GROUP = 'vector'
SERVICES = ['dynamodb']

_FLOOR_DIMS = 4
_LARGE_DIMS = 300


def _vec(n):
    return [{'N': '0.5'} for _ in range(n)]


def _vi(name, attr, dims, projection):
    return {'IndexName': name, 'VectorAttribute': {'AttributeName': attr}, 'Dimensions': dims,
            'DistanceFunction': 'COSINE', 'Projection': projection}


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
    """A vector index's VectorWriteRequestBytes adds the vector attribute name's byte length and
    every projected non-vector attribute's item size on top of the per-dimension cost. Two
    indexes each below the 1 KB floor in the same PutItem are floored independently.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvecbytes2-')

    keys_only = {'ProjectionType': 'KEYS_ONLY'}
    include_extra = {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['extra']}

    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[
            _vi('idx-s1', 'vs1', _FLOOR_DIMS, keys_only),
            _vi('idx-s2', 'vs2', _FLOOR_DIMS, keys_only),
            _vi('idx-l1', 'vl1', _LARGE_DIMS, keys_only),
            _vi('idx-l2', 'vLongAttr', _LARGE_DIMS, keys_only),
            _vi('idx-p', 'vp', _LARGE_DIMS, include_extra),
        ],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_vector_table_active(ctx, ddb, table, 5)

    def _put(pk, extra_attrs=None):
        item = {
            'pk': {'S': pk},
            'vs1': {'L': _vec(_FLOOR_DIMS)},
            'vs2': {'L': _vec(_FLOOR_DIMS)},
            'vl1': {'L': _vec(_LARGE_DIMS)},
            'vLongAttr': {'L': _vec(_LARGE_DIMS)},
            'vp': {'L': _vec(_LARGE_DIMS)},
        }
        if extra_attrs:
            item.update(extra_attrs)
        out = ddb.put_item(TableName=table, Item=item, ReturnConsumedCapacity='INDEXES')
        return out['ConsumedCapacity'].get('VectorIndexes') or {}

    # Two indexes below the floor in the same PutItem: each floors independently.
    per_index_a = _put('p1')
    s1 = per_index_a.get('idx-s1', {}).get('VectorWriteRequestBytes')
    s2 = per_index_a.get('idx-s2', {}).get('VectorWriteRequestBytes')
    assert s1 == 1024.0, f'idx-s1 ({_FLOOR_DIMS} dims, below floor): {s1!r}, expected 1024.0'
    assert s2 == 1024.0, (
        f'idx-s2 ({_FLOOR_DIMS} dims, below floor, same request as idx-s1): {s2!r}, '
        f'expected 1024.0 independently of idx-s1'
    )

    # Two above-floor indexes, identical dims and projection, differing only in the vector
    # attribute's name length ('vl1' = 3 bytes, 'vLongAttr' = 9 bytes).
    l1 = per_index_a.get('idx-l1', {}).get('VectorWriteRequestBytes')
    l2 = per_index_a.get('idx-l2', {}).get('VectorWriteRequestBytes')
    assert l1 == 1207.0, f'idx-l1: VectorWriteRequestBytes was {l1!r}, expected 1207.0'
    assert l2 == 1213.0, f'idx-l2: VectorWriteRequestBytes was {l2!r}, expected 1213.0'
    assert l2 - l1 == 6.0, (
        f'idx-l1 and idx-l2 differ only in the name length of the vector attribute (3 vs 9 '
        f'bytes); the VectorWriteRequestBytes delta was {l2 - l1!r}, expected 6.0'
    )

    # idx-p projects a non-vector attribute (INCLUDE ['extra']); the first item has no 'extra'.
    p_a = per_index_a.get('idx-p', {}).get('VectorWriteRequestBytes')
    assert p_a == 1206.0, f'idx-p with no projected non-vector attribute: {p_a!r}, expected 1206.0'

    # A second item, same vector, that also carries the projected 'extra' attribute.
    per_index_b = _put('p2', extra_attrs={'extra': {'S': '0123456789'}})
    p_b = per_index_b.get('idx-p', {}).get('VectorWriteRequestBytes')
    assert p_b == 1221.0, (
        f"idx-p with a projected 'extra' attribute ({{'S': '0123456789'}}, 15 item-size bytes): "
        f'{p_b!r}, expected 1221.0'
    )
    assert p_b - p_a == 15.0, (
        f"the only difference between the two items is the projected 'extra' attribute, whose "
        f"item size is 5 (name) + 10 (value) = 15 bytes; the VectorWriteRequestBytes delta was "
        f'{p_b - p_a!r}'
    )

    stored = ddb.get_item(TableName=table, Key={'pk': {'S': 'p2'}}, ConsistentRead=True)['Item']
    assert stored.get('extra') == {'S': '0123456789'}, (
        f"GetItem on p2 returned extra={stored.get('extra')!r}, expected {{'S': '0123456789'}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
