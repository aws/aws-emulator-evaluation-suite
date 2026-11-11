"""provisioned-table-rejects-an-on-demand-throughput-ceiling."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "provisioned-table-rejects-an-on-demand-throughput-ceiling"
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
    """The on-demand throughput ceilings apply only to an on-demand table, so setting them on a
    PROVISIONED table is refused -- a target that accepts both mixes two capacity models."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PROVISIONED',
                     ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5})
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    err = _error(
        lambda: ddb.update_table(TableName=table,
                                 OnDemandThroughput={'MaxReadRequestUnits': 100}),
        'an on-demand ceiling on a provisioned table',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = ('One or more parameter values were invalid: MaxReadRequestUnits for OnDemandThroughput '
                'cannot be specified when the table BillingMode is PROVISIONED')
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    t = ddb.describe_table(TableName=table)['Table']
    assert t['ProvisionedThroughput']['ReadCapacityUnits'] == 5, (
        'the refused update must leave provisioned throughput unchanged'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
