"""disable-kinesis-never-enabled."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disable-kinesis-never-enabled"
GROUP = 'errors'
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


def _error(fn):
    """(code, message) of the ClientError fn raises. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'expected a rejection, but the call SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisableKinesisStreamingDestination for a stream never enabled on the table raises ValidationException with the
    exact message and leaves no destination, while enabling and then disabling the same stream is accepted.
    """
    ddb = ctx.client('dynamodb')
    kinesis = ctx.client('kinesis')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    stream_name = ctx.unique_name('sim2real-behav-stream-')
    kinesis.create_stream(
        StreamName=stream_name,
        ShardCount=1,
        Tags={'sim2real': CHECK},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=stream_name)['StreamDescriptionSummary']['StreamStatus'],
        lambda s: s == 'ACTIVE',
        timeout_s=120,
        interval_s=2.0,
        description='kinesis stream ACTIVE',
    )
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)['StreamDescriptionSummary']['StreamARN']

    code, message = _error(
        lambda: ddb.disable_kinesis_streaming_destination(TableName=t, StreamArn=stream_arn)
    )
    assert code == 'ValidationException', (
        f'expected ValidationException for disabling a never-enabled destination, got {code}'
    )
    expected_message = (
        'Table is not in a valid state to enable Kinesis Streaming Destination: '
        'KinesisStreamingDestination must be ACTIVE to perform DISABLE operation.'
    )
    assert message == expected_message, f'expected message {expected_message!r}, got {message!r}'

    # The table must still report no streaming destinations at all.
    dests = ddb.describe_kinesis_streaming_destination(TableName=t)
    assert dests['KinesisDataStreamDestinations'] == [], dests

    # Positive control: enabling then disabling the SAME stream must succeed and
    # reach DISABLED -- without this, "rejects a never-enabled destination" is
    # indistinguishable from "rejects every DisableKinesisStreamingDestination call".
    ddb.enable_kinesis_streaming_destination(TableName=t, StreamArn=stream_arn)
    _poll_until(
        lambda: _destination_status(ddb, t, stream_arn),
        lambda s: s == 'ACTIVE',
        timeout_s=180,
        interval_s=3.0,
        description='streaming destination ACTIVE',
    )

    disable_resp = ddb.disable_kinesis_streaming_destination(TableName=t, StreamArn=stream_arn)
    assert disable_resp['DestinationStatus'] in ('DISABLING', 'DISABLED'), disable_resp
    _poll_until(
        lambda: _destination_status(ddb, t, stream_arn),
        lambda s: s == 'DISABLED',
        timeout_s=180,
        interval_s=3.0,
        description='streaming destination DISABLED',
    )


def _destination_status(ddb, table_name, stream_arn):
    dests = ddb.describe_kinesis_streaming_destination(TableName=table_name)['KinesisDataStreamDestinations']
    match = next((d for d in dests if d['StreamArn'] == stream_arn), None)
    return match['DestinationStatus'] if match else 'MISSING'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
