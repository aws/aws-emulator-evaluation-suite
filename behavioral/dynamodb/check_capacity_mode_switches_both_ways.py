"""capacity-mode-switches-both-ways."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "capacity-mode-switches-both-ways"
GROUP = 'state-machine'
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
    """A table switches on-demand to provisioned and back. Provisioned requires explicit throughput;
    switching back to on-demand drops it and stamps LastUpdateToPayPerRequestDateTime."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.update_table(TableName=table, BillingMode='PROVISIONED',
                     ProvisionedThroughput={'ReadCapacityUnits': 3, 'WriteCapacityUnits': 3})
    t = _wait_active(ddb, table)
    assert 'BillingModeSummary' in t, (
        f'DescribeTable must report BillingModeSummary after a mode switch, got {sorted(t)}'
    )
    assert t['BillingModeSummary']['BillingMode'] == 'PROVISIONED', (
        f"expected PROVISIONED, got {t['BillingModeSummary']}"
    )
    assert t['ProvisionedThroughput']['ReadCapacityUnits'] == 3, (
        f"expected 3 RCU, got {t['ProvisionedThroughput']}"
    )
    ddb.update_table(TableName=table, BillingMode='PAY_PER_REQUEST')
    t = _wait_active(ddb, table)
    assert 'BillingModeSummary' in t, (
        f'DescribeTable must report BillingModeSummary after switching back, got {sorted(t)}'
    )
    assert t['BillingModeSummary']['BillingMode'] == 'PAY_PER_REQUEST', (
        f"expected PAY_PER_REQUEST, got {t['BillingModeSummary']}"
    )
    assert t['BillingModeSummary'].get('LastUpdateToPayPerRequestDateTime'), (
        'switching to on-demand must stamp LastUpdateToPayPerRequestDateTime'
    )
    assert t['ProvisionedThroughput']['ReadCapacityUnits'] == 0, (
        f"an on-demand table reports zero provisioned capacity, got {t['ProvisionedThroughput']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
