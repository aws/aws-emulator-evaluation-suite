"""create-table-vector-index-validation-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-vector-index-validation-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


def _vi(name, attr, dims, fn='COSINE'):
    return {'IndexName': name, 'VectorAttribute': {'AttributeName': attr}, 'Dimensions': dims,
            'DistanceFunction': fn, 'Projection': {'ProjectionType': 'KEYS_ONLY'}}


def _budget_s(ctx, cap_s):
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _assert_never_created(ddb, table):
    code, message = _error(lambda: ddb.describe_table(TableName=table))
    assert code == 'ResourceNotFoundException', (
        f'{table}: CreateTable was refused but DescribeTable returned {code!r}, not '
        f'ResourceNotFoundException -- the table exists'
    )
    expected = f'Requested resource not found: Table: {table} not found'
    assert message == expected, f'{table}: unexpected DescribeTable message {message!r}'


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable refuses a vector index that violates a documented per-table rule, and the
    table it would have created never exists: Dimensions above 4096, more than 5 vector indexes
    on one table, and two indexes on the same attribute at different Dimensions.
    """
    ddb = ctx.client('dynamodb')

    # Positive control: a single, valid vector index is accepted and described back.
    control = ctx.unique_name('sim2real-behav-ddbvecval-control-')
    ddb.create_table(
        TableName=control,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[_vi('idx', 'emb', 16)],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=control))
    deadline = time.monotonic() + _budget_s(ctx, 240.0)
    tbl = ddb.describe_table(TableName=control)['Table']
    while not (tbl['TableStatus'] == 'ACTIVE' and tbl.get('VectorIndexes')
               and tbl['VectorIndexes'][0].get('IndexStatus') == 'ACTIVE'):
        assert time.monotonic() < deadline, f'control table never became ACTIVE: {tbl!r}'
        time.sleep(2)
        tbl = ddb.describe_table(TableName=control)['Table']
    assert tbl['VectorIndexes'][0]['Dimensions'] == 16, (
        f'control table vector index described back with Dimensions '
        f'{tbl["VectorIndexes"][0].get("Dimensions")!r}, expected 16'
    )

    # Dimensions above the documented maximum of 4096.
    over_dims = ctx.unique_name('sim2real-behav-ddbvecval-overdim-')
    code, message = _error(lambda: ddb.create_table(
        TableName=over_dims,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[_vi('idx', 'emb', 4097)],
    ))
    assert code == 'ValidationException', f'over-max Dimensions gave {code!r}, not ValidationException'
    expected = 'One or more parameter values were invalid: Number of dimensions must be between 1 and 4096 inclusive.'
    assert message == expected, f'over-max Dimensions message was {message!r}'
    _assert_never_created(ddb, over_dims)

    # More vector indexes than the documented per-table default of 5.
    too_many = ctx.unique_name('sim2real-behav-ddbvecval-toomany-')
    six_indexes = [_vi(f'idx{i}', f'emb{i}', 8) for i in range(6)]
    code, message = _error(lambda: ddb.create_table(
        TableName=too_many,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=six_indexes,
    ))
    assert code == 'ValidationException', f'six vector indexes gave {code!r}, not ValidationException'
    expected = 'One or more parameter values were invalid: VectorIndex count exceeds the per-table limit of 5'
    assert message == expected, f'too-many-indexes message was {message!r}'
    _assert_never_created(ddb, too_many)

    # The same vector attribute indexed twice at different Dimensions.
    conflict = ctx.unique_name('sim2real-behav-ddbvecval-conflict-')
    code, message = _error(lambda: ddb.create_table(
        TableName=conflict,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[_vi('idx-a', 'emb', 8), _vi('idx-b', 'emb', 16, fn='EUCLIDEAN')],
    ))
    assert code == 'ValidationException', f'conflicting Dimensions gave {code!r}, not ValidationException'
    expected = ("One or more parameter values were invalid: Conflicting attribute definition for "
                "'emb'. All VectorIndexes on the same vector attribute must use the same dimensions.")
    assert message == expected, f'conflicting-dimensions message was {message!r}'
    _assert_never_created(ddb, conflict)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
