"""put-item-and-search-vectors-return-consumed-capacity-invalid-enum-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-and-search-vectors-return-consumed-capacity-invalid-enum-rejected"
GROUP = "vector"
SERVICES = ["dynamodb"]
_VALIDATION_PUT = (
    "ValidationException",
    "1 validation error detected: Value 'BOGUS' at 'returnConsumedCapacity' failed to satisfy "
    "constraint: Member must satisfy enum value set: [INDEXES, TOTAL, NONE]",
)
_VALIDATION_SEARCH = (
    "ValidationException",
    "Value 'BOGUS' at 'returnConsumedCapacity' failed to satisfy constraint: Member must "
    "satisfy enum value set: [INDEXES, TOTAL, NONE]",
)
_VEC = [{'N': '1'}, {'N': '0'}, {'N': '0'}, {'N': '0'}]


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got = _error(fn)
    assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_vector_table_active(ddb, table, timeout_s=240):
    deadline = time.time() + timeout_s
    tbl = ddb.describe_table(TableName=table)['Table']
    while time.time() < deadline:
        tbl = ddb.describe_table(TableName=table)['Table']
        indexes = tbl.get('VectorIndexes', [])
        if (tbl['TableStatus'] == 'ACTIVE' and indexes
                and all(v.get('IndexStatus') == 'ACTIVE' for v in indexes)):
            return tbl
        time.sleep(2)
    raise AssertionError(
        f'table/vector index never became ACTIVE: {tbl["TableStatus"]!r} '
        f'{[(v.get("IndexName"), v.get("IndexStatus")) for v in indexes]!r}'
    )


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An out-of-enum ReturnConsumedCapacity is ValidationException on PutItem and SearchVectors
    alike, and a well-formed retry of each still performs its write or search correctly.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvecenum-')

    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'idx',
            'VectorAttribute': {'AttributeName': 'emb'},
            'Dimensions': 4,
            'DistanceFunction': 'COSINE',
            'Projection': {'ProjectionType': 'ALL'},
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), 'ResourceNotFoundException'))
    _wait_vector_table_active(ddb, table)

    expect_error(
        lambda: ddb.put_item(TableName=table, Item={'pk': {'S': 'v1'}, 'emb': {'L': _VEC}},
                             ReturnConsumedCapacity='BOGUS'),
        *_VALIDATION_PUT,
    )
    control_put = ddb.put_item(TableName=table, Item={'pk': {'S': 'v1'}, 'emb': {'L': _VEC}},
                               ReturnConsumedCapacity='TOTAL')
    assert control_put['ConsumedCapacity']['TableName'] == table, (
        f"the rejected PutItem must leave the table usable; the well-formed retry's "
        f"ConsumedCapacity was {control_put.get('ConsumedCapacity')!r}"
    )
    stored = ddb.get_item(TableName=table, Key={'pk': {'S': 'v1'}}, ConsistentRead=True)['Item']
    assert stored == {'pk': {'S': 'v1'}, 'emb': {'L': _VEC}}, (
        f'the well-formed retry must have written the item, read back {stored!r}'
    )

    expect_error(
        lambda: ddb.search_vectors(TableName=table, IndexName='idx', TopK=1, SearchVector=_VEC,
                                   ReturnConsumedCapacity='BOGUS'),
        *_VALIDATION_SEARCH,
    )
    deadline = time.time() + 90
    results = []
    while time.time() < deadline:
        results = ddb.search_vectors(TableName=table, IndexName='idx', TopK=1,
                                     SearchVector=_VEC)['SearchResults']
        if results:
            break
        time.sleep(1)
    assert [r['Item']['pk']['S'] for r in results] == ['v1'], (
        f'the rejected SearchVectors must leave the index searchable, got {results!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
