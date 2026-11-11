"""deep-dynamodb-1-ddbvec-search-vector-dimension-mismatch-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deep-dynamodb-1-ddbvec-search-vector-dimension-mismatch-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "plane:data", "dp:api")
def run(ctx) -> None:
    """A search vector shorter or longer than the index's Dimensions is a ValidationException.

    The model allows 1..4096 elements; the service checks against the index's declared Dimensions.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvec-')

    def _vi(name, fn):
        return {'IndexName': name, 'VectorAttribute': {'AttributeName': 'emb'}, 'Dimensions': 4,
                'DistanceFunction': fn, 'Projection': {'ProjectionType': 'ALL'}}

    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[_vi('idx-euc', 'EUCLIDEAN'), _vi('idx-dot', 'DOT_PRODUCT')],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_vector_table_active(ddb, table)
    ddb.put_item(TableName=table, Item={'pk': {'S': 'only'}, 'emb': {'L': _vec([1, 2, 3, 4])}})

    for idx in ('idx-euc', 'idx-dot'):
        got = []
        deadline = time.time() + 90
        while time.time() < deadline:
            got = [r['Item']['pk']['S'] for r in ddb.search_vectors(
                TableName=table, IndexName=idx, TopK=2,
                SearchVector=_vec([1, 2, 3, 4]))['SearchResults']]
            if got:
                break
            time.sleep(1)
        assert got == ['only'], f'positive control: 4-d search on {idx} returned {got!r}'

        for wrong in ([1, 2, 3], [1, 2, 3, 4, 5]):
            err = _error(lambda: ddb.search_vectors(TableName=table, IndexName=idx, TopK=2,
                                                    SearchVector=_vec(wrong)),
                         f'{len(wrong)}-element search vector on 4-d {idx}')
            assert err.get('Code') == 'ValidationException', (
                f'{idx}, {len(wrong)}-d: expected ValidationException, got {err!r}'
            )
            expected_msg = (f'Input search vector dimension {len(wrong)} does not match vector '
                            f'index dimension 4')
            assert err.get('Message') == expected_msg, (
                f'{idx}, {len(wrong)}-d: expected message {expected_msg!r}, '
                f'got {err.get("Message")!r}'
            )


def _vec(values):
    return [{'N': repr(float(x))} for x in values]


def _error(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the code IS the assertion
        err = (getattr(exc, 'response', None) or {}).get('Error')
        if not err:
            raise AssertionError(f'{what}: raised a non-service error {exc!r}') from exc
        return err
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


def _wait_vector_table_active(ddb, table, timeout_s=240):
    deadline = time.time() + timeout_s
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    tbl = ddb.describe_table(TableName=table)['Table']
    assert tbl.get('VectorIndexes'), (
        'CreateTable accepted VectorIndexes but DescribeTable reports none - the vector indexes '
        'were silently dropped'
    )
    while time.time() < deadline:
        tbl = ddb.describe_table(TableName=table)['Table']
        if tbl['TableStatus'] == 'ACTIVE' and all(
                v.get('IndexStatus') == 'ACTIVE' for v in tbl.get('VectorIndexes', [])):
            return tbl
        time.sleep(2)
    raise AssertionError(
        f'table/vector indexes never became ACTIVE: {tbl["TableStatus"]!r} '
        f'{[(v.get("IndexName"), v.get("IndexStatus")) for v in tbl.get("VectorIndexes", [])]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
