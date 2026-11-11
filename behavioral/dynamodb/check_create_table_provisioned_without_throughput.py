"""create-table-provisioned-without-throughput."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-provisioned-without-throughput"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected this CreateTable to be rejected, but it SUCCEEDED: {result!r}')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable in PROVISIONED mode without ProvisionedThroughput, and in PAY_PER_REQUEST mode with it,
    each raise ValidationException with the exact message and create no table; the same PROVISIONED call
    with 5/5 throughput succeeds.
    """
    ddb = ctx.client('dynamodb')
    ok_name = ctx.unique_name('sim2real-behav-goodprov-')
    ddb.create_table(
        TableName=ok_name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5},
        Tags=[{'Key': 'sim2real-check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=ok_name))
    ddb.get_waiter('table_exists').wait(TableName=ok_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ok_desc = ddb.describe_table(TableName=ok_name)['Table']
    assert ok_desc['TableStatus'] == 'ACTIVE', f'positive control table not ACTIVE: {ok_desc!r}'
    ok_throughput = ok_desc.get('ProvisionedThroughput', {})
    assert (ok_throughput.get('ReadCapacityUnits'), ok_throughput.get('WriteCapacityUnits')) == (5, 5), (
        f'expected explicit throughput 5/5 to be honored, got {ok_throughput!r}'
    )

    name1 = ctx.unique_name('sim2real-behav-badprov-')
    code1, msg1 = _error(
        lambda: ddb.create_table(
            TableName=name1,
            KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
            BillingMode='PROVISIONED',
        )
    )
    assert code1 == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code1}'
    expected1 = (
        'One or more parameter values were invalid: ReadCapacityUnits and WriteCapacityUnits '
        'must both be specified when BillingMode is PROVISIONED'
    )
    assert msg1 == expected1, f'expected message {expected1!r}, got {msg1!r}'
    stray1, stray1_msg = _error(lambda: ddb.describe_table(TableName=name1))
    assert stray1 == 'ResourceNotFoundException', 'a rejected CreateTable must not create a table'
    expected_nf1 = f'Requested resource not found: Table: {name1} not found'
    assert stray1_msg == expected_nf1, f'expected message {expected_nf1!r}, got {stray1_msg!r}'

    name2 = ctx.unique_name('sim2real-behav-badondemand-')
    code2, msg2 = _error(
        lambda: ddb.create_table(
            TableName=name2,
            KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5},
        )
    )
    assert code2 == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code2}'
    expected2 = (
        'One or more parameter values were invalid: Neither ReadCapacityUnits nor '
        'WriteCapacityUnits can be specified when BillingMode is PAY_PER_REQUEST'
    )
    assert msg2 == expected2, f'expected message {expected2!r}, got {msg2!r}'
    stray2, stray2_msg = _error(lambda: ddb.describe_table(TableName=name2))
    assert stray2 == 'ResourceNotFoundException', 'a rejected CreateTable must not create a table'
    expected_nf2 = f'Requested resource not found: Table: {name2} not found'
    assert stray2_msg == expected_nf2, f'expected message {expected_nf2!r}, got {stray2_msg!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
