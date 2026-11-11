"""kinesis-destination-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-destination-not-found"
GROUP = 'errors'
SERVICES = ['dynamodb']


def _error(fn):
    """The Error dict of a call that MUST be refused; RAISES if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {})
    raise AssertionError(f'real AWS refuses this call, but it SUCCEEDED and returned {result!r}')


def _wait_for_table_active(ddb, table_name, timeout_s=90.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table_name)['Table']['TableStatus']
        if status == 'ACTIVE':
            return status
        time.sleep(interval_s)
    raise AssertionError(f'table {table_name} never went ACTIVE in {timeout_s}s (last={status})')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeKinesisStreamingDestination on a nonexistent table raises ResourceNotFoundException with the exact
    message, while on a real table it returns no destinations.
    """
    ddb = ctx.client('dynamodb')

    table = ctx.unique_name('sim2real-behav-kds-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_for_table_active(ddb, table)

    live = ddb.describe_kinesis_streaming_destination(TableName=table)
    assert live['KinesisDataStreamDestinations'] == [], live

    missing = ctx.unique_name('sim2real-behav-no-such-table-')
    err = _error(lambda: ddb.describe_kinesis_streaming_destination(TableName=missing))
    assert err.get('Code') == 'ResourceNotFoundException', (
        f"expected ResourceNotFoundException, got {err.get('Code')}"
    )
    expected = f'Requested resource not found: Table: {missing} not found'
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
