"""create-table-vector-index-two-hash-search-schema-elements-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-vector-index-two-hash-search-schema-elements-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


def _wait_vector_index_active(ddb, table, timeout_s=240):
    deadline = time.monotonic() + timeout_s
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    tbl = ddb.describe_table(TableName=table)['Table']
    assert tbl.get('VectorIndexes'), (
        'CreateTable accepted VectorIndexes but DescribeTable reports none - the vector index '
        'was silently dropped'
    )
    while time.monotonic() < deadline:
        tbl = ddb.describe_table(TableName=table)['Table']
        if tbl['TableStatus'] == 'ACTIVE' and all(
                v.get('IndexStatus') == 'ACTIVE' for v in tbl.get('VectorIndexes', [])):
            return tbl
        time.sleep(2)
    raise AssertionError(
        f"table/vector index never became ACTIVE: {tbl['TableStatus']!r} "
        f"{[(v.get('IndexName'), v.get('IndexStatus')) for v in tbl.get('VectorIndexes', [])]!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A vector index SearchSchema takes at most one HASH element; CreateTable refuses a second
    one with the exact ValidationException, and the table it would have created never exists.
    """
    ddb = ctx.client('dynamodb')

    # Positive control: a single HASH element is accepted and described back.
    control = ctx.unique_name('sim2real-behav-ddbvec2hash-control-')
    ddb.create_table(
        TableName=control,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'tenant', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'vec-idx',
            'VectorAttribute': {'AttributeName': 'embedding'},
            'Dimensions': 8,
            'DistanceFunction': 'COSINE',
            'Projection': {'ProjectionType': 'ALL'},
            'SearchSchema': [{'AttributeName': 'tenant', 'SearchSchemaElementType': 'HASH'}],
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=control))
    control_tbl = _wait_vector_index_active(ddb, control)
    control_schema = control_tbl['VectorIndexes'][0]['SearchSchema']
    assert control_schema == [{'AttributeName': 'tenant', 'SearchSchemaElementType': 'HASH'}], (
        f'control: expected the single HASH element back, got {control_schema!r}'
    )

    # Two HASH elements: refused, and the table never exists.
    rejected = ctx.unique_name('sim2real-behav-ddbvec2hash-rejected-')
    code, message = _error(lambda: ddb.create_table(
        TableName=rejected,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'tenant', 'AttributeType': 'S'},
            {'AttributeName': 'region', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'vec-idx',
            'VectorAttribute': {'AttributeName': 'embedding'},
            'Dimensions': 8,
            'DistanceFunction': 'COSINE',
            'Projection': {'ProjectionType': 'ALL'},
            'SearchSchema': [
                {'AttributeName': 'tenant', 'SearchSchemaElementType': 'HASH'},
                {'AttributeName': 'region', 'SearchSchemaElementType': 'HASH'},
            ],
        }],
    ))
    assert code == 'ValidationException', f'two HASH elements gave {code!r}, not ValidationException'
    expected_message = (
        "One or more parameter values were invalid: Value '2' at 'SearchSchema' failed to "
        "satisfy constraint: Member must have HASH count less than or equal to 1"
    )
    assert message == expected_message, f'two HASH elements message was {message!r}'

    code2, message2 = _error(lambda: ddb.describe_table(TableName=rejected))
    assert code2 == 'ResourceNotFoundException', (
        f'{rejected}: CreateTable was refused but DescribeTable returned {code2!r}, not '
        f'ResourceNotFoundException -- the table exists'
    )
    expected2 = f'Requested resource not found: Table: {rejected} not found'
    assert message2 == expected2, f'{rejected}: unexpected DescribeTable message {message2!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
