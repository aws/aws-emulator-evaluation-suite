"""keys-only-and-all-projections-are-exempt-from-the-attribute-budget."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "keys-only-and-all-projections-are-exempt-from-the-attribute-budget"
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
    """The 100-attribute budget counts only user-specified INCLUDE attributes, so any number of
    KEYS_ONLY and ALL indexes is accepted -- the exemption, asserted positively."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ads = [{'AttributeName': 'pk', 'AttributeType': 'S'}]
    gsis = []
    for i in range(6):
        ads.append({'AttributeName': f'g{i}', 'AttributeType': 'S'})
        gsis.append({'IndexName': f'idx{i}',
                     'KeySchema': [{'AttributeName': f'g{i}', 'KeyType': 'HASH'}],
                     'Projection': {'ProjectionType': 'ALL' if i % 2 else 'KEYS_ONLY'}})
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=ads, GlobalSecondaryIndexes=gsis,
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    t = _wait_active(ddb, table)
    got = sorted(i['IndexName'] for i in t.get('GlobalSecondaryIndexes') or [])
    assert got == [f'idx{i}' for i in range(6)], f'expected all six indexes, got {got}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
