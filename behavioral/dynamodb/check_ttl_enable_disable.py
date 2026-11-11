"""ttl-enable-disable."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ttl-enable-disable"
GROUP = 'ttl'
SERVICES = ['dynamodb']


def _poll_until(probe, predicate, *, timeout_s=180, interval_s=5.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TTL can be enabled; DescribeTimeToLive converges to ENABLED with the configured attribute.

    Note: real AWS requires ~1 hour between enable and disable, so we only
    test enabling and verifying the describe response.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.update_time_to_live(TableName=table, TimeToLiveSpecification={'Enabled': True, 'AttributeName': 'expires_at'})

    def probe():
        return ddb.describe_time_to_live(TableName=table)['TimeToLiveDescription']

    ttl = _poll_until(
        probe,
        lambda t: t['TimeToLiveStatus'] == 'ENABLED',
        description=f'TTL on {table} reaching ENABLED',
    )
    assert ttl['TimeToLiveStatus'] == 'ENABLED', ttl
    assert ttl['AttributeName'] == 'expires_at', ttl

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
