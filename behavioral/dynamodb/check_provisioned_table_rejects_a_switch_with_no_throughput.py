"""provisioned-table-rejects-a-switch-with-no-throughput."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "provisioned-table-rejects-a-switch-with-no-throughput"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


def _error(call, what):
    """The Error dict from a call that MUST be refused."""
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the error IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Switching to PROVISIONED without naming ReadCapacityUnits and WriteCapacityUnits is refused:
    there is no default to fall back on."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    err = _error(lambda: ddb.update_table(TableName=table, BillingMode='PROVISIONED'),
                 'a switch to PROVISIONED with no throughput')
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = ('One or more parameter values were invalid: ProvisionedThroughput must be specified when '
                'BillingMode is PROVISIONED')
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    t = ddb.describe_table(TableName=table)['Table']
    assert t['BillingModeSummary']['BillingMode'] == 'PAY_PER_REQUEST', (
        'the refused switch must leave the table on-demand'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
