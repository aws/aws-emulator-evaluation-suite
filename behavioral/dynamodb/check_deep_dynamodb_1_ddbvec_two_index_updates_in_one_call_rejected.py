"""deep-dynamodb-1-ddbvec-two-index-updates-in-one-call-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deep-dynamodb-1-ddbvec-two-index-updates-in-one-call-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']

_QUERY = [1.0, 0.0, 0.0, 0.0]


def _create(name):
    return {'Create': {'IndexName': name, 'VectorAttribute': {'AttributeName': 'emb'},
                       'Dimensions': 4, 'DistanceFunction': 'COSINE',
                       'Projection': {'ProjectionType': 'ALL'}}}


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
    """UpdateTable takes ONE vector-index create or delete per call; two are LimitExceededException.

    The refused call leaves the index set unchanged; a single Delete is applied, after which a
    search on that index is a ValidationException.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvec-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{'IndexName': 'idx-orig', 'VectorAttribute': {'AttributeName': 'emb'},
                        'Dimensions': 4, 'DistanceFunction': 'COSINE',
                        'Projection': {'ProjectionType': 'ALL'}}],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    # DeleteTable is refused while a vector index is being created or deleted.
    ctx.on_cleanup(lambda: _delete_table_when_settled(ddb, table))
    _wait_vector_table_active(ddb, table)
    ddb.put_item(TableName=table, Item={'pk': {'S': 'only'}, 'emb': {'L': _vec(_QUERY)}})

    def _search(idx):
        return [r['Item']['pk']['S'] for r in ddb.search_vectors(
            TableName=table, IndexName=idx, TopK=3, SearchVector=_vec(_QUERY))['SearchResults']]

    got = []
    deadline = time.time() + 90
    while time.time() < deadline:
        got = _search('idx-orig')
        if got:
            break
        time.sleep(1)
    assert got == ['only'], f'idx-orig returned {got!r} before the updates'

    for what, updates in (('two Creates', [_create('idx-new1'), _create('idx-new2')]),
                          ('Create + Delete', [_create('idx-new1'),
                                               {'Delete': {'IndexName': 'idx-orig'}}])):
        err = _error(lambda: ddb.update_table(TableName=table, VectorIndexUpdates=updates),
                     f'UpdateTable with {what}')
        assert err.get('Code') == 'LimitExceededException', (
            f'{what}: expected LimitExceededException, got {err!r}'
        )
        expected_msg = ('Subscriber limit exceeded: Only 1 online index can be created or '
                        'deleted simultaneously per table')
        assert err.get('Message') == expected_msg, (
            f'{what}: expected message {expected_msg!r}, got {err.get("Message")!r}'
        )
        tbl = ddb.describe_table(TableName=table)['Table']
        names = sorted(v['IndexName'] for v in tbl.get('VectorIndexes', []))
        assert names == ['idx-orig'], f'{what}: refused update still changed the indexes: {names!r}'
        assert tbl['VectorIndexes'][0].get('IndexStatus') == 'ACTIVE', (
            f'{what}: idx-orig left ACTIVE: {tbl["VectorIndexes"][0]!r}'
        )
        assert _search('idx-orig') == ['only'], f'{what}: idx-orig stopped answering'

    # Positive control: the one-element form is applied.
    resp = ddb.update_table(TableName=table, VectorIndexUpdates=[{'Delete': {'IndexName': 'idx-orig'}}])
    st = [(v.get('IndexName'), v.get('IndexStatus'))
          for v in resp['TableDescription'].get('VectorIndexes', [])]
    assert st == [('idx-orig', 'DELETING')], f'single Delete described {st!r}'
    gone = None
    deadline = time.time() + 240
    while time.time() < deadline:
        tbl = ddb.describe_table(TableName=table)['Table']
        if not tbl.get('VectorIndexes') and tbl['TableStatus'] == 'ACTIVE':
            gone = True
            break
        time.sleep(2)
    assert gone, f'idx-orig was never removed: {tbl.get("VectorIndexes")!r}'
    err = _error(lambda: _search('idx-orig'), 'SearchVectors on the deleted index')
    assert err.get('Code') == 'ValidationException', (
        f'search on the deleted index: expected ValidationException, got {err!r}'
    )
    expected_msg = 'The table does not have the specified index: idx-orig'
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
