"""deep-dynamodb-1-ddbvec-index-tracks-update-and-delete-item."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deep-dynamodb-1-ddbvec-index-tracks-update-and-delete-item"
GROUP = 'vector'
SERVICES = ['dynamodb']

_QUERY = [0.0, 0.0, 0.0, 0.0]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """After UpdateItem moves x4 to 0.5, DeleteItem removes x1 and REMOVE strips x2's vector, a EUCLIDEAN search
    returns exactly [x4, x3] with scores 0.5 and 3, while x2 stays in the table without its vector.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvec-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{'IndexName': 'idx-euc', 'VectorAttribute': {'AttributeName': 'emb'},
                        'Dimensions': 4, 'DistanceFunction': 'EUCLIDEAN',
                        'Projection': {'ProjectionType': 'ALL'}}],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_vector_table_active(ddb, table)
    for x in (1, 2, 3, 4):
        ddb.put_item(TableName=table, Item={'pk': {'S': f'x{x}'}, 'tag': {'S': 'keep'},
                                            'emb': {'L': _vec([float(x), 0, 0, 0])}})

    def _search():
        return [(r['Item']['pk']['S'], float(r['Score'])) for r in ddb.search_vectors(
            TableName=table, IndexName='idx-euc', TopK=10,
            SearchVector=_vec(_QUERY))['SearchResults']]

    def _until(want_ids):
        got = []
        deadline = time.time() + 90
        while time.time() < deadline:
            got = _search()
            if [pk for pk, _ in got] == want_ids:
                return got
            time.sleep(1)
        return got

    before = _until(['x1', 'x2', 'x3', 'x4'])
    assert [pk for pk, _ in before] == ['x1', 'x2', 'x3', 'x4'], f'initial search {before!r}'

    ddb.update_item(TableName=table, Key={'pk': {'S': 'x4'}}, UpdateExpression='SET emb = :e',
                    ExpressionAttributeValues={':e': {'L': _vec([0.5, 0, 0, 0])}})
    ddb.delete_item(TableName=table, Key={'pk': {'S': 'x1'}})
    ddb.update_item(TableName=table, Key={'pk': {'S': 'x2'}}, UpdateExpression='REMOVE emb')

    still = ddb.get_item(TableName=table, Key={'pk': {'S': 'x2'}}, ConsistentRead=True).get('Item')
    assert still == {'pk': {'S': 'x2'}, 'tag': {'S': 'keep'}}, (
        f'x2 should remain in the table without its vector, GetItem gave {still!r}'
    )

    after = _until(['x4', 'x3'])
    assert [pk for pk, _ in after] == ['x4', 'x3'], (
        f'after update/delete/remove the index returned {after!r}, expected [x4, x3]'
    )
    assert abs(after[0][1] - 0.5) < 1e-4, f'moved item x4 scored {after[0][1]!r}, expected 0.5'
    assert abs(after[1][1] - 3.0) < 1e-4, f'x3 scored {after[1][1]!r}, expected 3.0'


def _vec(values):
    return [{'N': repr(float(x))} for x in values]


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
