"""deep-dynamodb-1-ddbvec-delete-unknown-vector-index-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deep-dynamodb-1-ddbvec-delete-unknown-vector-index-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']

_QUERY = [1.0, 0.0, 0.0, 0.0]


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:negative-classes",
    "concern:data-plane",
    "plane:control",
    "plane:data",
    "dp:api",
)
def run(ctx) -> None:
    """UpdateTable deleting a vector index the table lacks raises ResourceNotFoundException with the exact message
    and leaves both indexes ACTIVE; deleting a real index removes only it, and a search on it then raises
    ValidationException with the exact message.
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
        VectorIndexes=[_vi('idx-keep', 'EUCLIDEAN'), _vi('idx-drop', 'DOT_PRODUCT')],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    # DeleteTable is refused while a vector index is being created or deleted.
    ctx.on_cleanup(lambda: _delete_table_when_settled(ddb, table))
    _wait_vector_table_active(ddb, table)
    ddb.put_item(TableName=table, Item={'pk': {'S': 'only'}, 'emb': {'L': _vec(_QUERY)}})

    def _search(idx):
        return [r['Item']['pk']['S'] for r in ddb.search_vectors(
            TableName=table, IndexName=idx, TopK=3, SearchVector=_vec(_QUERY))['SearchResults']]

    for idx in ('idx-keep', 'idx-drop'):
        got = []
        deadline = time.time() + 90
        while time.time() < deadline:
            got = _search(idx)
            if got:
                break
            time.sleep(1)
        assert got == ['only'], f'{idx} returned {got!r} before any delete'

    err = _error(lambda: ddb.update_table(
        TableName=table, VectorIndexUpdates=[{'Delete': {'IndexName': 'idx-dropped'}}]),
        'UpdateTable deleting a nonexistent vector index')
    assert err.get('Code') == 'ResourceNotFoundException', (
        f'expected ResourceNotFoundException, got {err!r}'
    )
    expected_msg = f'Requested resource not found: Index idx-dropped for table {table}'
    assert err.get('Message') == expected_msg, (
        f'expected message {expected_msg!r}, got {err.get("Message")!r}'
    )
    tbl = ddb.describe_table(TableName=table)['Table']
    st = sorted((v['IndexName'], v.get('IndexStatus')) for v in tbl.get('VectorIndexes', []))
    assert st == [('idx-drop', 'ACTIVE'), ('idx-keep', 'ACTIVE')], f'after the refusal: {st!r}'

    # Positive control: deleting a real index removes exactly that one.
    ddb.update_table(TableName=table, VectorIndexUpdates=[{'Delete': {'IndexName': 'idx-drop'}}])
    names = None
    deadline = time.time() + 240
    while time.time() < deadline:
        tbl = ddb.describe_table(TableName=table)['Table']
        names = sorted(v['IndexName'] for v in tbl.get('VectorIndexes', []))
        if names == ['idx-keep'] and tbl['TableStatus'] == 'ACTIVE':
            break
        time.sleep(2)
    assert names == ['idx-keep'], f'after deleting idx-drop the table has {names!r}'
    assert _search('idx-keep') == ['only'], 'the sibling index stopped answering after the delete'
    err = _error(lambda: _search('idx-drop'), 'SearchVectors on the deleted index')
    assert err.get('Code') == 'ValidationException', (
        f'search on the deleted index: expected ValidationException, got {err!r}'
    )
    expected_msg = 'The table does not have the specified index: idx-drop'
    assert err.get('Message') == expected_msg, (
        f'search on the deleted index: expected message {expected_msg!r}, got {err.get("Message")!r}'
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


def _delete_table_when_settled(ddb, table, timeout_s=1500):
    deadline = time.time() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table)
            return
        except Exception as exc:  # noqa: BLE001
            code = (getattr(exc, 'response', None) or {}).get('Error', {}).get('Code')
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException' or time.time() > deadline:
                raise
        time.sleep(5)


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
