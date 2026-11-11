"""provisioned-throughput-on-pay-per-request."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioned-throughput-on-pay-per-request"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error(fn):
    """The Error dict of a call that MUST be refused; RAISES if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {})
    raise AssertionError(f'real AWS refuses this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable with ProvisionedThroughput and BillingMode=PAY_PER_REQUEST fails with
    ValidationException and creates no table, while the same request without throughput succeeds."""
    ddb = ctx.client('dynamodb')

    control_name = ctx.unique_name('sim2real-behav-ppr-control-')
    ddb.create_table(
        TableName=control_name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=control_name))
    ddb.get_waiter('table_exists').wait(TableName=control_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    control_status = ddb.describe_table(TableName=control_name)['Table']['TableStatus']
    assert control_status == 'ACTIVE', (
        f'positive control: PAY_PER_REQUEST CreateTable with no throughput block must succeed, '
        f'got status {control_status!r}'
    )

    name = ctx.unique_name('sim2real-behav-ppr-with-throughput-')
    err = _error(
        lambda: ddb.create_table(
            TableName=name,
            KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5},
        )
    )
    assert err.get('Code') == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {err.get('Code')}"
    expected = ('One or more parameter values were invalid: Neither ReadCapacityUnits nor '
                'WriteCapacityUnits can be specified when BillingMode is PAY_PER_REQUEST')
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    exists_err = _error(lambda: ddb.describe_table(TableName=name))
    assert exists_err.get('Code') == 'ResourceNotFoundException', (
        'a rejected CreateTable must not leave a stray table behind'
    )
    expected_missing = f'Requested resource not found: Table: {name} not found'
    assert exists_err.get('Message') == expected_missing, (
        f"expected message {expected_missing!r}, got {exists_err.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
