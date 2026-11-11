"""deep-dynamodb-1-ddbvec-unknown-index-name-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deep-dynamodb-1-ddbvec-unknown-index-name-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']

_QUERY = [1.0, 0.0, 0.0, 0.0]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "plane:data", "dp:api")
def run(ctx) -> None:
    """SearchVectors naming a missing index (a near-miss name, a case variant) raises ValidationException with the
    exact message naming it, while the three real indexes answer before and remain afterwards.
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
        VectorIndexes=[_vi('idx-cos', 'COSINE'), _vi('idx-euc', 'EUCLIDEAN'),
                       _vi('idx-dot', 'DOT_PRODUCT')],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_vector_table_active(ddb, table)
    ddb.put_item(TableName=table, Item={'pk': {'S': 'only'}, 'emb': {'L': _vec(_QUERY)}})

    def _control():
        for idx in ('idx-cos', 'idx-euc', 'idx-dot'):
            got = []
            deadline = time.time() + 90
            while time.time() < deadline:
                got = [r['Item']['pk']['S'] for r in ddb.search_vectors(
                    TableName=table, IndexName=idx, TopK=3,
                    SearchVector=_vec(_QUERY))['SearchResults']]
                if got:
                    break
                time.sleep(1)
            assert got == ['only'], f'positive control: {idx} returned {got!r}, expected [only]'

    _control()

    for bad in ('idx-cosine', 'IDX-COS'):
        err = _error(lambda: ddb.search_vectors(TableName=table, IndexName=bad, TopK=3,
                                                SearchVector=_vec(_QUERY)),
                     f'SearchVectors on nonexistent index {bad!r}')
        assert err.get('Code') == 'ValidationException', (
            f'index {bad!r}: expected ValidationException, got {err!r}'
        )
        expected_msg = f'The table does not have the specified index: {bad}'
        assert err.get('Message') == expected_msg, (
            f'index {bad!r}: expected message {expected_msg!r}, got {err.get("Message")!r}'
        )

    # Effect absent: the refusals created nothing and the real indexes are untouched.
    names = sorted(v['IndexName'] for v in
                   ddb.describe_table(TableName=table)['Table'].get('VectorIndexes', []))
    assert names == ['idx-cos', 'idx-dot', 'idx-euc'], f'vector indexes after refusals: {names!r}'
    _control()


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
