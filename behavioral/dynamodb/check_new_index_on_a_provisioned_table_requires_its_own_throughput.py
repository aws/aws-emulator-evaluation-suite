"""new-index-on-a-provisioned-table-requires-its-own-throughput."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "new-index-on-a-provisioned-table-requires-its-own-throughput"
GROUP = 'gsi'
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
    """ProvisionedThroughput is required for a new index ONLY when the base table is provisioned --
    conditional requiredness, which a target treating the field as always-optional gets wrong."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PROVISIONED',
                     ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5})
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    err = _error(
        lambda: ddb.update_table(
            TableName=table,
            AttributeDefinitions=[{'AttributeName': 'g1', 'AttributeType': 'S'}],
            GlobalSecondaryIndexUpdates=[{'Create': {
                'IndexName': 'idx1',
                'KeySchema': [{'AttributeName': 'g1', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'}}}]),
        'a new index on a provisioned table with no ProvisionedThroughput',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = ('One or more parameter values were invalid: Both ReadCapacityUnits and WriteCapacityUnits '
                'must be specified for index: idx1')
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    assert not ddb.describe_table(TableName=table)['Table'].get('GlobalSecondaryIndexes'), (
        'the refused create must add no index'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
