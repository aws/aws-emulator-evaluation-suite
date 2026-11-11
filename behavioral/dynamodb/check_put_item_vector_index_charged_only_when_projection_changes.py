"""put-item-vector-index-charged-only-when-projection-changes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-vector-index-charged-only-when-projection-changes"
GROUP = "vector"
SERVICES = ["dynamodb"]

_DIMS = 4
_VEC = [{'N': '1'}, {'N': '0'}, {'N': '0'}, {'N': '0'}]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _vi(name, projection):
    return {
        'IndexName': name,
        'VectorAttribute': {'AttributeName': 'emb'},
        'Dimensions': _DIMS,
        'DistanceFunction': 'COSINE',
        'Projection': projection,
    }


def _wait_vector_table_active(ddb, table, n_indexes, timeout_s=240):
    deadline = time.time() + timeout_s
    tbl = ddb.describe_table(TableName=table)['Table']
    while time.time() < deadline:
        tbl = ddb.describe_table(TableName=table)['Table']
        indexes = tbl.get('VectorIndexes', [])
        if (tbl['TableStatus'] == 'ACTIVE' and len(indexes) == n_indexes
                and all(v.get('IndexStatus') == 'ACTIVE' for v in indexes)):
            return tbl
        time.sleep(2)
    raise AssertionError(
        f'table/vector indexes never became ACTIVE: {tbl["TableStatus"]!r} '
        f'{[(v.get("IndexName"), v.get("IndexStatus")) for v in indexes]!r}'
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """PutItem ReturnConsumedCapacity=INDEXES charges a vector index only when the write
    changes an attribute that index projects; an identical overwrite charges no vector
    index, and ReturnConsumedCapacity=TOTAL carries no VectorIndexes or Table field.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvecproj-')

    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[
            _vi('idx-all', {'ProjectionType': 'ALL'}),
            _vi('idx-keys', {'ProjectionType': 'KEYS_ONLY'}),
        ],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), 'ResourceNotFoundException'))
    _wait_vector_table_active(ddb, table, 2)

    # First write: both indexes materialize a fresh entry for the vector attribute.
    put1 = ddb.put_item(TableName=table,
                        Item={'pk': {'S': 'v1'}, 'emb': {'L': _VEC}, 'note': {'S': 'first'}},
                        ReturnConsumedCapacity='INDEXES')
    cc1 = (put1.get('ConsumedCapacity') or {}).get('VectorIndexes') or {}
    assert set(cc1) == {'idx-all', 'idx-keys'}, (
        f'a write creating a new vector entry must charge every vector index over the '
        f'attribute, got {sorted(cc1)}'
    )

    # Second write: same pk, same vector, but 'note' changes. idx-all projects 'note' (ALL);
    # idx-keys does not (KEYS_ONLY).
    put2 = ddb.put_item(TableName=table,
                        Item={'pk': {'S': 'v1'}, 'emb': {'L': _VEC}, 'note': {'S': 'second'}},
                        ReturnConsumedCapacity='INDEXES')
    cc2 = (put2.get('ConsumedCapacity') or {}).get('VectorIndexes') or {}
    assert set(cc2) == {'idx-all'}, (
        f"changing 'note', which only idx-all projects, must charge idx-all and not "
        f'idx-keys; VectorIndexes was {sorted(cc2)}'
    )

    # Third write: byte-for-byte identical to the second. Nothing projected by either index
    # changed, so neither index is charged.
    put3 = ddb.put_item(TableName=table,
                        Item={'pk': {'S': 'v1'}, 'emb': {'L': _VEC}, 'note': {'S': 'second'}},
                        ReturnConsumedCapacity='INDEXES')
    cc3 = put3.get('ConsumedCapacity') or {}
    assert 'VectorIndexes' not in cc3, (
        f'an identical overwrite must charge no vector index, got {cc3.get("VectorIndexes")!r}'
    )

    # Fourth write: a real change again, but requested with TOTAL instead of INDEXES: no
    # per-index breakdown and no table breakdown, only the top-level fields.
    put4 = ddb.put_item(TableName=table,
                        Item={'pk': {'S': 'v1'}, 'emb': {'L': _VEC}, 'note': {'S': 'third'}},
                        ReturnConsumedCapacity='TOTAL')
    cc4 = put4.get('ConsumedCapacity') or {}
    assert 'VectorIndexes' not in cc4, f'TOTAL must carry no VectorIndexes field, got {cc4!r}'
    assert 'Table' not in cc4, f'TOTAL must carry no Table field, got {cc4!r}'

    stored = ddb.get_item(TableName=table, Key={'pk': {'S': 'v1'}}, ConsistentRead=True)['Item']
    assert stored.get('note') == {'S': 'third'}, (
        f"GetItem after the fourth write returned note={stored.get('note')!r}, expected "
        f"{{'S': 'third'}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
