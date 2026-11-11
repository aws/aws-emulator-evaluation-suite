"""update-table-sets-and-clears-the-on-demand-read-ceiling."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-sets-and-clears-the-on-demand-read-ceiling"
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


def _delete_table(ddb, table, timeout_s=300):
    """Teardown: DeleteTable is refused while the last throughput update is still settling;
    retry to a deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table)
            return
        except ClientError as exc:
            code = exc.response['Error']['Code']
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException' or time.monotonic() >= deadline:
                raise
            time.sleep(2)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MaxReadRequestUnits caps an on-demand table's read throughput, and -1 REMOVES the cap rather
    than setting it to minus one. A target storing the sentinel literally reports -1 back."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.update_table(TableName=table,
                     OnDemandThroughput={'MaxReadRequestUnits': 100, 'MaxWriteRequestUnits': 200})
    t = _wait_active(ddb, table)
    assert t['OnDemandThroughput']['MaxReadRequestUnits'] == 100, (
        f"expected a read ceiling of 100, got {t.get('OnDemandThroughput')}"
    )
    ddb.update_table(TableName=table, OnDemandThroughput={'MaxReadRequestUnits': -1})
    t = _wait_active(ddb, table)
    got = (t.get('OnDemandThroughput') or {}).get('MaxReadRequestUnits')
    assert got != 100, 'the ceiling must change when it is removed'
    assert got in (-1, None), (
        f'-1 removes the ceiling rather than becoming the value; got {got!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
