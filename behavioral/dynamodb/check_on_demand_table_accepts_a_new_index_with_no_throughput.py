"""on-demand-table-accepts-a-new-index-with-no-throughput."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "on-demand-table-accepts-a-new-index-with-no-throughput"
GROUP = 'gsi'
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
    """The other half of the same rule: on an on-demand table a new index needs NO throughput, and it
    inherits the base table's capacity mode."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.update_table(
        TableName=table,
        AttributeDefinitions=[{'AttributeName': 'g1', 'AttributeType': 'S'}],
        GlobalSecondaryIndexUpdates=[{'Create': {
            'IndexName': 'idx1',
            'KeySchema': [{'AttributeName': 'g1', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'}}}])
    # Deliberately NOT waiting for ACTIVE: a real GSI backfill runs 5-15 minutes, past this
    # check's whole budget (measured: >240s). The claim under test is the state the create
    # ENTERS, observable at once -- and exactly what an engine with no in-progress state misses.
    t = ddb.describe_table(TableName=table)['Table']
    idx = (t.get('GlobalSecondaryIndexes') or [])
    assert [i['IndexName'] for i in idx] == ['idx1'], f'expected index idx1, got {idx}'
    assert idx[0].get('IndexStatus') == 'CREATING', (
        f"a new index starts CREATING rather than appearing ACTIVE at once, got "
        f"{idx[0].get('IndexStatus')}"
    )
    assert t['BillingModeSummary']['BillingMode'] == 'PAY_PER_REQUEST', (
        f"the table must stay on-demand, got {t.get('BillingModeSummary')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
