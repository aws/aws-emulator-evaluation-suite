"""put-item-vector-of-wrong-dimension-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-item-vector-of-wrong-dimension-rejected"
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
    """A write whose embedding length contradicts the index dimensions is refused at PutItem, not
    accepted and silently left out of the index."""
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
        lambda: ddb.put_item(TableName=table, Item={'pk': {'S': 'bad'},
                                                    'embedding': {'L': [{'N': '1'}, {'N': '0'}]}}),
        'a PutItem whose embedding has the wrong dimension',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = (
        'One or more parameter values were invalid. Invalid size for parameter embedding, '
        'Expected: 3, Actual: 2 IndexName: cos'
    )
    assert err.get('Message') == expected, f"unexpected message {err.get('Message')!r}"
    assert 'Item' not in ddb.get_item(TableName=table, Key={'pk': {'S': 'bad'}}, ConsistentRead=True), (
        'the refused write must not create the item'
    )

    # A vector list holding a non-number element.
    err2 = _error_code(
        lambda: ddb.put_item(TableName=table, Item={'pk': {'S': 'bad2'},
                                                    'embedding': {'L': [{'N': '1'}, {'S': 'x'}, {'N': '0'}]}}),
        'a PutItem whose embedding has a non-number element',
    )
    assert err2.get('Code') == 'ValidationException', f"expected ValidationException, got {err2.get('Code')}"
    expected2 = (
        'One or more parameter values were invalid. Invalid type for parameter embedding[1], '
        'Expected: 32-bit floating point number, Actual: S. IndexName: cos'
    )
    assert err2.get('Message') == expected2, f"unexpected message {err2.get('Message')!r}"
    assert 'Item' not in ddb.get_item(TableName=table, Key={'pk': {'S': 'bad2'}}, ConsistentRead=True), (
        'the refused write must not create the item'
    )

    # A vector attribute that is not a list at all.
    err3 = _error_code(
        lambda: ddb.put_item(TableName=table, Item={'pk': {'S': 'bad3'},
                                                    'embedding': {'S': 'not-a-vector'}}),
        'a PutItem whose embedding is not a list',
    )
    assert err3.get('Code') == 'ValidationException', f"expected ValidationException, got {err3.get('Code')}"
    expected3 = (
        'One or more parameter values were invalid. Invalid type for parameter embedding, '
        'Expected: 32-bit floating point number list IndexName: cos'
    )
    assert err3.get('Message') == expected3, f"unexpected message {err3.get('Message')!r}"
    assert 'Item' not in ddb.get_item(TableName=table, Key={'pk': {'S': 'bad3'}}, ConsistentRead=True), (
        'the refused write must not create the item'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
