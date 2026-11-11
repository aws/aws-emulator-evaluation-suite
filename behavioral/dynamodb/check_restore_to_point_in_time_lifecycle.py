"""restore-to-point-in-time-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-to-point-in-time-lifecycle"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _delete_table_with_retry(ddb, name, timeout_s=600, interval_s=2.0):
    """A table restored via RestoreTableToPointInTime can stay CREATING for minutes, and AWS
    refuses DeleteTable on a CREATING table with ResourceInUseException, so that code is retried
    up to timeout_s; any other error, or the deadline, raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=name)
            return
        except ClientError as exc:
            if exc.response['Error']['Code'] != 'ResourceInUseException' or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_continuous_backups_ready(ddb, name, timeout_s=90):
    return _poll_until(
        lambda: ddb.describe_continuous_backups(TableName=name)['ContinuousBackupsDescription'],
        lambda d: d['ContinuousBackupsStatus'] == 'ENABLED',
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f'continuous backups ready for {name}',
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RestoreTableToPointInTime produces a new table whose state is visible
    via DescribeTable. Exercises RestoreTableToPointInTime, DescribeTable."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=t, Item={'pk': {'S': 'seed'}, 'v': {'S': '1'}})
    _wait_continuous_backups_ready(ddb, t)

    ddb.update_continuous_backups(TableName=t, PointInTimeRecoverySpecification={'PointInTimeRecoveryEnabled': True})
    _poll_until(
        lambda: ddb.describe_continuous_backups(TableName=t)['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus'],
        lambda s: s == 'ENABLED',
        timeout_s=60,
        interval_s=2.0,
        description='PITR enabled',
    )

    target_name = ctx.unique_name('sim2real-behav-pitr-restored-')
    ctx.on_cleanup(lambda: _delete_table_with_retry(ddb, target_name))

    # Immediately after PITR turns on, a restorable time may take a few
    # seconds to become available -- retry via _poll_until.
    last_err: list[Exception] = []

    def _try_restore():
        try:
            return ddb.restore_table_to_point_in_time(
                SourceTableName=t,
                TargetTableName=target_name,
                UseLatestRestorableTime=True,
            )['TableDescription']
        except ClientError as exc:
            last_err.append(exc)
            return None

    table_desc = _poll_until(
        _try_restore,
        lambda d: d is not None,
        timeout_s=30,
        interval_s=3.0,
        description='restore_table_to_point_in_time succeeds once a restorable time exists',
    )
    assert table_desc is not None, (
        f'restore_table_to_point_in_time never succeeded: {last_err[-1] if last_err else None}'
    )
    assert table_desc['TableStatus'] in ('CREATING', 'ACTIVE')
    assert table_desc['RestoreSummary']['SourceTableArn'].endswith(f'table/{t}')

    # Restoring to ACTIVE can take several minutes even for a tiny table, so
    # this check asserts only that the restored table is visible and CREATING
    # or ACTIVE via DescribeTable, not that it reaches ACTIVE.
    described = _poll_until(
        lambda: ddb.describe_table(TableName=target_name)['Table'],
        lambda tbl: tbl['TableStatus'] in ('CREATING', 'ACTIVE'),
        timeout_s=60,
        interval_s=3.0,
        description='restored table visible via DescribeTable',
    )
    assert described['TableName'] == target_name
    assert described['RestoreSummary']['SourceTableArn'].endswith(f'table/{t}')


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
