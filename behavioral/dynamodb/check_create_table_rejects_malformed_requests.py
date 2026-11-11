"""create-table-rejects-malformed-requests."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-rejects-malformed-requests"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
ERR_NOT_FOUND = 'ResourceNotFoundException'


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    naming what came back, rather than returning a sentinel a mismatch could be confused with."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be rejected, but it SUCCEEDED and returned {result!r}')


def _safe_delete_table(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response['Error']['Code'] != ERR_NOT_FOUND:
            raise


def _assert_not_created(ddb, table_name):
    code, message = _error(lambda: ddb.describe_table(TableName=table_name))
    assert code == ERR_NOT_FOUND, f'expected {table_name!r} to not exist, DescribeTable gave {code!r}'
    expected = f'Requested resource not found: Table: {table_name} not found'
    assert message == expected, f'expected message {expected!r}, got {message!r}'


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable rejects five malformed requests with ValidationException and its exact
    message, each graded together with a later, independent DescribeTable call proving no
    table was created.
    """
    ddb = ctx.client('dynamodb')
    lax_ddb = ctx.client('dynamodb', config=Config(parameter_validation=False))
    wait_fast = {'Delay': 2, 'MaxAttempts': 60}

    control_name = ctx.unique_name('sim2real-behav-ddb-createreject-control-')
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, control_name))
    ddb.create_table(
        TableName=control_name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
    )
    ddb.get_waiter('table_exists').wait(TableName=control_name, WaiterConfig=wait_fast)
    control = ddb.describe_table(TableName=control_name)['Table']
    assert control['TableStatus'] == 'ACTIVE', (
        f'positive control: expected {control_name} ACTIVE, got {control["TableStatus"]!r}'
    )

    gsi_name = ctx.unique_name('sim2real-behav-ddb-createreject-gsiinc-')
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, gsi_name))
    code, message = _error(lambda: ddb.create_table(
        TableName=gsi_name,
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'gsipk', 'AttributeType': 'S'},
        ],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        GlobalSecondaryIndexes=[{
            'IndexName': 'gsi1',
            'KeySchema': [{'AttributeName': 'gsipk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'INCLUDE'},
        }],
        BillingMode='PAY_PER_REQUEST',
    ))
    assert code == ERR_VALIDATION, f'GSI INCLUDE with no NonKeyAttributes: expected {ERR_VALIDATION}, got {code!r}'
    expected = 'One or more parameter values were invalid: ProjectionType is INCLUDE, but NonKeyAttributes is not specified'
    assert message == expected, f'GSI INCLUDE with no NonKeyAttributes: expected message {expected!r}, got {message!r}'
    _assert_not_created(ddb, gsi_name)

    lsi_name = ctx.unique_name('sim2real-behav-ddb-createreject-lsiinc-')
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, lsi_name))
    code, message = _error(lambda: ddb.create_table(
        TableName=lsi_name,
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'lsisk', 'AttributeType': 'S'},
        ],
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [
                {'AttributeName': 'pk', 'KeyType': 'HASH'},
                {'AttributeName': 'lsisk', 'KeyType': 'RANGE'},
            ],
            'Projection': {'ProjectionType': 'INCLUDE'},
        }],
        BillingMode='PAY_PER_REQUEST',
    ))
    assert code == ERR_VALIDATION, f'LSI INCLUDE with no NonKeyAttributes: expected {ERR_VALIDATION}, got {code!r}'
    assert message == expected, f'LSI INCLUDE with no NonKeyAttributes: expected message {expected!r}, got {message!r}'
    _assert_not_created(ddb, lsi_name)

    code, message = _error(lambda: lax_ddb.create_table(
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PAY_PER_REQUEST',
    ))
    assert code == ERR_VALIDATION, f'no TableName: expected {ERR_VALIDATION}, got {code!r}'
    expected_no_name = "The parameter 'TableName' is required but was not present in the request"
    assert message == expected_no_name, f'no TableName: expected message {expected_no_name!r}, got {message!r}'

    samekey_name = ctx.unique_name('sim2real-behav-ddb-createreject-samekey-')
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, samekey_name))
    code, message = _error(lambda: ddb.create_table(
        TableName=samekey_name,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'pk', 'KeyType': 'RANGE'},
        ],
        BillingMode='PAY_PER_REQUEST',
    ))
    assert code == ERR_VALIDATION, f'same attribute as HASH and RANGE: expected {ERR_VALIDATION}, got {code!r}'
    expected_samekey = 'Invalid KeySchema: Some index key attribute have no definition'
    assert message == expected_samekey, (
        f'same attribute as HASH and RANGE: expected message {expected_samekey!r}, got {message!r}'
    )
    _assert_not_created(ddb, samekey_name)

    streamfv_name = ctx.unique_name('sim2real-behav-ddb-createreject-streamfv-')
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, streamfv_name))
    code, message = _error(lambda: ddb.create_table(
        TableName=streamfv_name,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PAY_PER_REQUEST',
        StreamSpecification={'StreamEnabled': False, 'StreamViewType': 'NEW_IMAGE'},
    ))
    assert code == ERR_VALIDATION, f'StreamEnabled false with a StreamViewType: expected {ERR_VALIDATION}, got {code!r}'
    expected_stream = (
        'One or more parameter values were invalid: Table is being created with a stream '
        'disabled, UpdateViewType should not be specified'
    )
    assert message == expected_stream, (
        f'StreamEnabled false with a StreamViewType: expected message {expected_stream!r}, got {message!r}'
    )
    _assert_not_created(ddb, streamfv_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
