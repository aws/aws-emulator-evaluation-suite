"""search-vectors-dimension-mismatch-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-vectors-dimension-mismatch-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']


def _error_code(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the code IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """A search vector whose length differs from the index dimensions is refused, and the message
    states both dimensions so a caller can fix the call."""
    import time

    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'cos',
            'VectorAttribute': {'AttributeName': 'embedding'},
            'Dimensions': 3,
            'DistanceFunction': 'COSINE',
            'Projection': {'ProjectionType': 'ALL'},
        }],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    # Fail FAST when CreateTable ignored `VectorIndexes` outright: an index that is absent
    # immediately after create is never going to appear. Poll only while the
    # index EXISTS but is still backfilling, which is the state a real create passes through.
    described = ddb.describe_table(TableName=table)['Table'].get('VectorIndexes', [])
    assert described, (
        'CreateTable accepted VectorIndexes but DescribeTable reports none, so the vector index '
        'was silently dropped'
    )
    deadline = time.time() + 120
    while time.time() < deadline and described[0].get('IndexStatus') != 'ACTIVE':
        time.sleep(1)
        described = ddb.describe_table(TableName=table)['Table'].get('VectorIndexes', [])
        assert described, 'the vector index disappeared while it was backfilling'
    assert described[0].get('IndexStatus') == 'ACTIVE', (
        f"the vector index never became ACTIVE: {described[0].get('IndexStatus')!r}"
    )
    err = _error_code(
        lambda: ddb.search_vectors(TableName=table, IndexName='cos', TopK=1, SearchVector=[{'N': '1'}]),
        'a SearchVectors whose vector has the wrong dimension',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = 'Input search vector dimension 1 does not match vector index dimension 3'
    assert err.get('Message') == expected, f"the message must state both dimensions, got {err.get('Message')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
