"""update-table-creates-at-most-one-index-per-call."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-table-creates-at-most-one-index-per-call"
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
    """Only one secondary index may be created per UpdateTable call, so a request carrying two Create
    actions is refused outright and neither index appears."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    err = _error(
        lambda: ddb.update_table(
            TableName=table,
            AttributeDefinitions=[{'AttributeName': 'g1', 'AttributeType': 'S'},
                                  {'AttributeName': 'g2', 'AttributeType': 'S'}],
            GlobalSecondaryIndexUpdates=[
                {'Create': {'IndexName': 'idx1',
                            'KeySchema': [{'AttributeName': 'g1', 'KeyType': 'HASH'}],
                            'Projection': {'ProjectionType': 'ALL'}}},
                {'Create': {'IndexName': 'idx2',
                            'KeySchema': [{'AttributeName': 'g2', 'KeyType': 'HASH'}],
                            'Projection': {'ProjectionType': 'ALL'}}},
            ]),
        'an UpdateTable creating two indexes at once',
    )
    # LimitExceededException, NOT ValidationException: the request is well formed, it just asks
    # for more concurrent index work than DynamoDB will do. Measured against real AWS.
    assert err.get('Code') == 'LimitExceededException', (
        f"expected LimitExceededException, got {err.get('Code')}"
    )
    expected = 'Subscriber limit exceeded: Only 1 online index can be created or deleted simultaneously per table'
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    assert not ddb.describe_table(TableName=table)['Table'].get('GlobalSecondaryIndexes'), (
        'a refused multi-create must leave the table with no index at all'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
