"""deep-dynamodb-1-ddbvec-topk-above-100-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deep-dynamodb-1-ddbvec-topk-above-100-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']

_N_ITEMS = 3


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "plane:data", "dp:api")
def run(ctx) -> None:
    """SearchVectors with TopK above 100 raises ValidationException with the exact range message, while TopK=100
    returns the three stored items; the model declares no maximum, so only AWS's answer shows the cap.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvec-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{'IndexName': 'idx-cos', 'VectorAttribute': {'AttributeName': 'emb'},
                        'Dimensions': 4, 'DistanceFunction': 'COSINE',
                        'Projection': {'ProjectionType': 'ALL'}}],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_vector_table_active(ddb, table)
    for i in range(_N_ITEMS):
        ddb.put_item(TableName=table, Item={'pk': {'S': f'i{i}'},
                                            'emb': {'L': _vec([1.0, float(i), 0.0, 0.0])}})

    res = []
    deadline = time.time() + 90
    while time.time() < deadline:
        res = ddb.search_vectors(TableName=table, IndexName='idx-cos', TopK=100,
                                 SearchVector=_vec([1, 0, 0, 0]))['SearchResults']
        if len(res) == _N_ITEMS:
            break
        time.sleep(1)
    assert sorted(r['Item']['pk']['S'] for r in res) == [f'i{i}' for i in range(_N_ITEMS)], (
        f'positive control: TopK=100 returned {[r["Item"]["pk"]["S"] for r in res]!r}'
    )

    for top_k in (101, 1000):
        err = _error(lambda: ddb.search_vectors(TableName=table, IndexName='idx-cos', TopK=top_k,
                                                SearchVector=_vec([1, 0, 0, 0])),
                     f'SearchVectors with TopK={top_k}')
        assert err.get('Code') == 'ValidationException', (
            f'TopK={top_k}: expected ValidationException, got {err!r}'
        )
        expected_msg = (f"Provided TopK value '{top_k}' is out of valid range. The value must "
                        f"be between 1 and 100 inclusive")
        assert err.get('Message') == expected_msg, (
            f'TopK={top_k}: expected message {expected_msg!r}, got {err.get("Message")!r}'
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
        'CreateTable accepted VectorIndexes but DescribeTable reports none - the vector index '
        'was silently dropped'
    )
    while time.time() < deadline:
        tbl = ddb.describe_table(TableName=table)['Table']
        if tbl['TableStatus'] == 'ACTIVE' and all(
                v.get('IndexStatus') == 'ACTIVE' for v in tbl.get('VectorIndexes', [])):
            return tbl
        time.sleep(2)
    raise AssertionError(
        f'table/vector index never became ACTIVE: {tbl["TableStatus"]!r} '
        f'{[(v.get("IndexName"), v.get("IndexStatus")) for v in tbl.get("VectorIndexes", [])]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
