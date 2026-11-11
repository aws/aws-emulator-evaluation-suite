"""update-table-rejects-a-duplicate-index-name."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-table-rejects-a-duplicate-index-name"
GROUP = 'gsi'
SERVICES = ['dynamodb']


def _error(call, what):
    """The Error dict from a call that MUST be refused."""
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the error IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


def _wait_active(ddb, table, deadline_s=240):
    """Poll DescribeTable until the table is ACTIVE with no index still mutating."""
    import time

    end = time.time() + deadline_s
    while time.time() < end:
        t = ddb.describe_table(TableName=table)['Table']
        busy = [i for i in t.get('GlobalSecondaryIndexes') or []
                if i.get('IndexStatus') != 'ACTIVE']
        if t['TableStatus'] == 'ACTIVE' and not busy:
            return t
        time.sleep(3)
    raise AssertionError(f'{table} never settled to ACTIVE within {deadline_s}s')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A new index's name must be unique among the table's existing indexes, so adding a second index
    under a name already in use is refused and the original is left untouched."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'g1', 'AttributeType': 'S'}],
        GlobalSecondaryIndexes=[{'IndexName': 'dupname',
                                 'KeySchema': [{'AttributeName': 'g1', 'KeyType': 'HASH'}],
                                 'Projection': {'ProjectionType': 'ALL'}}],
        BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    _wait_active(ddb, table)
    err = _error(
        lambda: ddb.update_table(
            TableName=table,
            AttributeDefinitions=[{'AttributeName': 'g2', 'AttributeType': 'S'}],
            GlobalSecondaryIndexUpdates=[{'Create': {
                'IndexName': 'dupname',
                'KeySchema': [{'AttributeName': 'g2', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'}}}]),
        'adding a second index named `dupname`',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = 'Attempting to create an index which already exists'
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    idx = [i for i in ddb.describe_table(TableName=table)['Table'].get('GlobalSecondaryIndexes') or []]
    assert [i['IndexName'] for i in idx] == ['dupname'], f'the original index must survive, got {idx}'
    assert idx[0]['KeySchema'][0]['AttributeName'] == 'g1', (
        'the refused create must not have rewritten the existing index'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
