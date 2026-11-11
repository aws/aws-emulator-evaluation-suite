"""put-item-vector-write-validation-and-search-projection."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-vector-write-validation-and-search-projection"
GROUP = 'vector'
SERVICES = ['dynamodb']

_DIMENSIONS = 4


def _vec(values):
    return [{'N': repr(float(v))} for v in values]


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


def _budget_s(ctx, cap_s):
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "concern:representation", "plane:control", "plane:data", "dp:api")
def run(ctx) -> None:
    """A non-numeric list element, a non-list vector attribute, or a SearchSchema element naming
    an undeclared attribute is a ValidationException that leaves no item or table behind.
    SearchVectors omits the vector attribute from a result unless ProjectionExpression names it."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvecwrite-')

    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'tier', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'idx',
            'VectorAttribute': {'AttributeName': 'emb'},
            'Dimensions': _DIMENSIONS,
            'DistanceFunction': 'COSINE',
            'Projection': {'ProjectionType': 'ALL'},
            'SearchSchema': [{'AttributeName': 'tier', 'SearchSchemaElementType': 'INLINE_FILTER'}],
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    deadline = time.monotonic() + _budget_s(ctx, 240.0)
    tbl = ddb.describe_table(TableName=table)['Table']
    while not (tbl['TableStatus'] == 'ACTIVE' and tbl.get('VectorIndexes')
               and tbl['VectorIndexes'][0].get('IndexStatus') == 'ACTIVE'):
        assert time.monotonic() < deadline, f'table/vector index never became ACTIVE: {tbl!r}'
        time.sleep(2)
        tbl = ddb.describe_table(TableName=table)['Table']

    # A list element that is not a number.
    code, message = _error(lambda: ddb.put_item(TableName=table, Item={
        'pk': {'S': 'bad-element'}, 'tier': {'S': 'gold'},
        'emb': {'L': [{'N': '1'}, {'S': 'x'}, {'N': '2'}, {'N': '3'}]},
    }))
    assert code == 'ValidationException', f'non-numeric list element gave {code!r}'
    expected = ('One or more parameter values were invalid. Invalid type for parameter emb[1], '
                'Expected: 32-bit floating point number, Actual: S. IndexName: idx')
    assert message == expected, f'non-numeric list element message was {message!r}'
    absent = ddb.get_item(TableName=table, Key={'pk': {'S': 'bad-element'}}, ConsistentRead=True)
    assert 'Item' not in absent, f'the rejected write left an item behind: {absent.get("Item")!r}'

    # A vector attribute that is not a list.
    code, message = _error(lambda: ddb.put_item(TableName=table, Item={
        'pk': {'S': 'not-a-list'}, 'tier': {'S': 'gold'}, 'emb': {'N': '1.0'},
    }))
    assert code == 'ValidationException', f'non-list vector attribute gave {code!r}'
    expected = ('One or more parameter values were invalid. Invalid type for parameter emb, '
                'Expected: 32-bit floating point number list IndexName: idx')
    assert message == expected, f'non-list vector attribute message was {message!r}'
    absent = ddb.get_item(TableName=table, Key={'pk': {'S': 'not-a-list'}}, ConsistentRead=True)
    assert 'Item' not in absent, f'the rejected write left an item behind: {absent.get("Item")!r}'

    # A SearchSchema element naming an attribute never declared in AttributeDefinitions (the
    # empty string is never declared, same as any other undeclared name).
    bad_schema = ctx.unique_name('sim2real-behav-ddbvecwrite-badschema-')
    code, message = _error(lambda: ddb.create_table(
        TableName=bad_schema,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'idx',
            'VectorAttribute': {'AttributeName': 'emb'},
            'Dimensions': _DIMENSIONS,
            'DistanceFunction': 'COSINE',
            'Projection': {'ProjectionType': 'ALL'},
            'SearchSchema': [{'AttributeName': '', 'SearchSchemaElementType': 'INLINE_FILTER'}],
        }],
    ))
    assert code == 'ValidationException', f'empty-string SearchSchema key gave {code!r}'
    expected = ('One or more parameter values were invalid: One element in SearchSchema is not '
                'defined in attribute definitions')
    assert message == expected, f'empty-string SearchSchema key message was {message!r}'
    not_found_code, not_found_message = _error(lambda: ddb.describe_table(TableName=bad_schema))
    assert not_found_code == 'ResourceNotFoundException', (
        f'CreateTable was refused but DescribeTable returned {not_found_code!r} for {bad_schema}'
    )

    # Positive control, and the projection claim: a valid write is searchable, and the vector
    # attribute is absent from the result unless ProjectionExpression names it.
    ddb.put_item(TableName=table, Item={
        'pk': {'S': 'good'}, 'tier': {'S': 'gold'}, 'emb': {'L': _vec([1.0, 0.0, 0.0, 0.0])},
    })

    def _search(**kwargs):
        search_deadline = time.monotonic() + _budget_s(ctx, 90.0)
        while True:
            results = ddb.search_vectors(TableName=table, IndexName='idx', TopK=5,
                                         SearchVector=_vec([1.0, 0.0, 0.0, 0.0]), **kwargs
                                         )['SearchResults']
            if results:
                return results
            assert time.monotonic() < search_deadline, 'the written vector never became searchable'
            time.sleep(2)

    default = _search()
    assert [r['Item']['pk']['S'] for r in default] == ['good'], (
        f'expected only the written item back, got {[r["Item"] for r in default]!r}'
    )
    assert set(default[0]['Item']) == {'pk', 'tier'}, (
        f'a default SearchVectors projection included the vector attribute: '
        f'{sorted(default[0]["Item"])!r}'
    )

    projected = _search(ProjectionExpression='emb, pk')
    assert set(projected[0]['Item']) == {'pk', 'emb'}, (
        f'ProjectionExpression naming the vector attribute did not return it: '
        f'{sorted(projected[0]["Item"])!r}'
    )
    assert projected[0]['Item']['emb'] == {'L': _vec([1.0, 0.0, 0.0, 0.0])}, (
        f'the projected vector attribute did not round-trip: {projected[0]["Item"]["emb"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
