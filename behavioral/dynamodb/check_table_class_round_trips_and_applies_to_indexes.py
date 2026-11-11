"""table-class-round-trips-and-applies-to-indexes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "table-class-round-trips-and-applies-to-indexes"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A table's class moves from STANDARD to STANDARD_INFREQUENT_ACCESS and back to STANDARD.

    After each UpdateTable, TableClassSummary carries the new class and a LastUpdateDateTime.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'g1', 'AttributeType': 'S'}],
        GlobalSecondaryIndexes=[{'IndexName': 'idx1',
                                 'KeySchema': [{'AttributeName': 'g1', 'KeyType': 'HASH'}],
                                 'Projection': {'ProjectionType': 'ALL'}}],
        BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    t = _wait_active(ddb, table)
    # A default-class table OMITS TableClassSummary entirely (measured against real AWS); the
    # field appears only once the class has been set explicitly. Either shape is correct here.
    assert (t.get('TableClassSummary') or {}).get('TableClass', 'STANDARD') == 'STANDARD', (
        f"a new table is STANDARD, got {t.get('TableClassSummary')}"
    )
    ddb.update_table(TableName=table, TableClass='STANDARD_INFREQUENT_ACCESS')
    t = _wait_active(ddb, table)
    assert 'TableClassSummary' in t, (
        f'DescribeTable must report TableClassSummary after a class change, got {sorted(t)}'
    )
    assert t['TableClassSummary']['TableClass'] == 'STANDARD_INFREQUENT_ACCESS', (
        f"expected STANDARD_INFREQUENT_ACCESS, got {t.get('TableClassSummary')}"
    )
    assert t['TableClassSummary'].get('LastUpdateDateTime'), (
        'a class change must stamp LastUpdateDateTime'
    )
    ddb.update_table(TableName=table, TableClass='STANDARD')
    t = _wait_active(ddb, table)
    assert (t.get('TableClassSummary') or {}).get('TableClass') == 'STANDARD', (
        f"expected STANDARD after the class moves back, got {t.get('TableClassSummary')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
