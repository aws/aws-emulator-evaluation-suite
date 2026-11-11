"""create-table-unused-attribute-definitions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-unused-attribute-definitions"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
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
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable whose AttributeDefinitions name an attribute no key schema uses raises ValidationException
    with the exact message and creates no table, while the same call without that attribute succeeds.
    """
    ddb = ctx.client('dynamodb')
    name = ctx.unique_name('sim2real-behav-unused-attr-')
    key_schema = [{'AttributeName': 'pk', 'KeyType': 'HASH'}]
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, name))

    ddb.create_table(
        TableName=name,
        KeySchema=key_schema,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
    )
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.delete_table(TableName=name)
    ddb.get_waiter('table_not_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    code, message = _error(
        lambda: ddb.create_table(
            TableName=name,
            KeySchema=key_schema,
            AttributeDefinitions=[
                {'AttributeName': 'pk', 'AttributeType': 'S'},
                {'AttributeName': 'never_used', 'AttributeType': 'S'},
            ],
            BillingMode='PAY_PER_REQUEST',
        )
    )
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}'
    expected_msg = (
        'One or more parameter values were invalid: Number of attributes in KeySchema does not '
        'exactly match number of attributes defined in AttributeDefinitions'
    )
    assert message == expected_msg, f'expected message {expected_msg!r}, got {message!r}'

    exists_code, exists_msg = _error(lambda: ddb.describe_table(TableName=name))
    assert exists_code == 'ResourceNotFoundException', (
        'a rejected CreateTable must not leave a stray table behind'
    )
    expected_nf = f'Requested resource not found: Table: {name} not found'
    assert exists_msg == expected_nf, f'expected message {expected_nf!r}, got {exists_msg!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
