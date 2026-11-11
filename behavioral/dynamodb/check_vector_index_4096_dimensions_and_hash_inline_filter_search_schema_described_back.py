"""vector-index-4096-dimensions-and-hash-inline-filter-search-schema-described-back."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "vector-index-4096-dimensions-and-hash-inline-filter-search-schema-described-back"
GROUP = 'vector'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTable reports Dimensions 4096 for a vector index created at that size, and a
    SearchSchema combining a HASH and an INLINE_FILTER element round-trips both, in order.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvecdim-')
    search_schema = [
        {'AttributeName': 'tenant', 'SearchSchemaElementType': 'HASH'},
        {'AttributeName': 'cat', 'SearchSchemaElementType': 'INLINE_FILTER'},
    ]
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'tenant', 'AttributeType': 'S'},
            {'AttributeName': 'cat', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'vec-idx',
            'VectorAttribute': {'AttributeName': 'embedding'},
            'Dimensions': 4096,
            'DistanceFunction': 'COSINE',
            'Projection': {'ProjectionType': 'ALL'},
            'SearchSchema': search_schema,
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    tbl = _wait_vector_index_active(ddb, table)
    idx = tbl['VectorIndexes'][0]
    assert idx['Dimensions'] == 4096, f"expected Dimensions 4096, got {idx.get('Dimensions')!r}"
    assert idx['SearchSchema'] == search_schema, (
        f"expected SearchSchema {search_schema!r} in order, got {idx.get('SearchSchema')!r}"
    )
    assert idx['DistanceFunction'] == 'COSINE', f"expected COSINE, got {idx.get('DistanceFunction')!r}"


def _wait_vector_index_active(ddb, table, timeout_s=240):
    deadline = time.monotonic() + timeout_s
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    tbl = ddb.describe_table(TableName=table)['Table']
    assert tbl.get('VectorIndexes'), (
        'CreateTable accepted VectorIndexes but DescribeTable reports none'
    )
    while time.monotonic() < deadline:
        tbl = ddb.describe_table(TableName=table)['Table']
        if tbl['TableStatus'] == 'ACTIVE' and all(
                v.get('IndexStatus') == 'ACTIVE' for v in tbl.get('VectorIndexes', [])):
            return tbl
        time.sleep(2)
    raise AssertionError(
        f"table/vector index never became ACTIVE: {tbl['TableStatus']!r} "
        f"{[(v.get('IndexName'), v.get('IndexStatus')) for v in tbl.get('VectorIndexes', [])]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
