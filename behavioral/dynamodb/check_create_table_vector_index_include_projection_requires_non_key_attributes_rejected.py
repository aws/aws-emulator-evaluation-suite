"""create-table-vector-index-include-projection-requires-non-key-attributes-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-vector-index-include-projection-requires-non-key-attributes-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


def _vi(name, attr, dims, projection):
    return {'IndexName': name, 'VectorAttribute': {'AttributeName': attr}, 'Dimensions': dims,
            'DistanceFunction': 'COSINE', 'Projection': projection}


def _budget_s(ctx, cap_s):
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_vector_table_active(ctx, ddb, table, cap_s=240.0):
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    tbl = ddb.describe_table(TableName=table)['Table']
    while True:
        tbl = ddb.describe_table(TableName=table)['Table']
        indexes = tbl.get('VectorIndexes', [])
        if (tbl['TableStatus'] == 'ACTIVE' and indexes
                and all(v.get('IndexStatus') == 'ACTIVE' for v in indexes)):
            return tbl
        if time.monotonic() >= deadline:
            raise AssertionError(
                f'table/vector index never became ACTIVE in time: status '
                f'{tbl["TableStatus"]!r}, indexes '
                f'{[(v.get("IndexName"), v.get("IndexStatus")) for v in indexes]!r}'
            )
        time.sleep(2)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "plane:data",
      "dp:api")
def run(ctx) -> None:
    """CreateTable refuses a vector index with Projection INCLUDE and no NonKeyAttributes, and the
    table it would have created never exists.
    """
    ddb = ctx.client('dynamodb')

    # Positive control: INCLUDE with a non-empty NonKeyAttributes is accepted and described back.
    control = ctx.unique_name('sim2real-behav-ddbvecincl-control-')
    ddb.create_table(
        TableName=control,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[_vi('idx', 'emb', 16,
                            {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['extra']})],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=control))
    tbl = _wait_vector_table_active(ctx, ddb, control)
    assert tbl['VectorIndexes'][0]['Projection'] == {
        'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['extra']
    }, f'control table described back {tbl["VectorIndexes"][0]["Projection"]!r}'

    # INCLUDE with no NonKeyAttributes at all.
    missing = ctx.unique_name('sim2real-behav-ddbvecincl-missing-')
    code, message = _error(lambda: ddb.create_table(
        TableName=missing,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[_vi('idx', 'emb', 16, {'ProjectionType': 'INCLUDE'})],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    ))
    assert code == 'ValidationException', f'INCLUDE with no NonKeyAttributes: expected ValidationException, got {code!r}'
    expected_message = (
        "One or more parameter values were invalid: ProjectionType is INCLUDE, but "
        "NonKeyAttributes is not specified"
    )
    assert message == expected_message, f'INCLUDE with no NonKeyAttributes: unexpected message {message!r}'
    code2, message2 = _error(lambda: ddb.describe_table(TableName=missing))
    assert code2 == 'ResourceNotFoundException', (
        f'{missing}: CreateTable was refused but DescribeTable returned {code2!r}, not '
        f'ResourceNotFoundException -- the table exists'
    )
    expected_not_found = f'Requested resource not found: Table: {missing} not found'
    assert message2 == expected_not_found, f'{missing}: unexpected DescribeTable message {message2!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
