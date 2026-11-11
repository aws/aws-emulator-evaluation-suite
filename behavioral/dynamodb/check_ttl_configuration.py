"""ttl-configuration."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ttl-configuration"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


def _poll_until(probe, predicate, *, timeout_s=90, interval_s=3.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _delete_table_if_present(ddb, table):
    try:
        ddb.delete_table(TableName=table)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
            raise


def _poll_not_found(fn, *, expected_message, description):
    """Poll fn() (a read against the deleted table) until it raises
    ResourceNotFoundException. DeleteTable is async: the table lingers in
    DELETING and reads keep succeeding for a while, so an immediate read
    after DeleteTable is not evidence of anything."""
    def _probe():
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            assert code == 'ResourceNotFoundException', (
                f'expected ResourceNotFoundException for {description}, got {code}'
            )
            message = exc.response.get('Error', {}).get('Message')
            assert message == expected_message, (
                f'expected {expected_message!r} for {description}, got {message!r}'
            )
            return True
        return False

    _poll_until(_probe, lambda gone: gone, timeout_s=180, interval_s=3.0, description=description)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new table's TTL is DISABLED and UpdateTimeToLive converges to ENABLED on expires_at; after DeleteTable,
    DescribeTable and DescribeTimeToLive raise ResourceNotFoundException with the exact message.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_if_present(ddb, table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    baseline = ddb.describe_time_to_live(TableName=table)['TimeToLiveDescription']
    assert baseline.get('TimeToLiveStatus') == 'DISABLED', f'fresh table must start DISABLED, got {baseline}'

    ddb.update_time_to_live(TableName=table, TimeToLiveSpecification={'Enabled': True, 'AttributeName': 'expires_at'})

    ttl = _poll_until(
        lambda: ddb.describe_time_to_live(TableName=table)['TimeToLiveDescription'],
        lambda d: d.get('TimeToLiveStatus') == 'ENABLED',
        description='TTL to converge to the terminal ENABLED status',
    )
    assert ttl['AttributeName'] == 'expires_at', f"expected AttributeName='expires_at', got {ttl}"

    ddb.delete_table(TableName=table)

    not_found = f'Requested resource not found: Table: {table} not found'
    _poll_not_found(
        lambda: ddb.describe_table(TableName=table),
        expected_message=not_found,
        description='describe_table to report the deleted table not-found',
    )
    _poll_not_found(
        lambda: ddb.describe_time_to_live(TableName=table),
        expected_message=not_found,
        description='describe_time_to_live to report the deleted table not-found',
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
