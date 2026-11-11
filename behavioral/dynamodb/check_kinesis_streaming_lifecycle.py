"""kinesis-streaming-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "kinesis-streaming-lifecycle"
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Streaming destination transitions ENABLING->ACTIVE->DISABLING->DISABLED
    are observable via Describe/Update/Enable/Disable calls."""
    ddb = ctx.client('dynamodb')
    kinesis = ctx.client('kinesis')

    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    stream_name = ctx.unique_name('sim2real-behav-stream-')
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=stream_name)['StreamDescriptionSummary']['StreamStatus'],
        lambda s: s == 'ACTIVE',
        timeout_s=90,
        interval_s=2.0,
        description='kinesis stream ACTIVE',
    )
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)['StreamDescriptionSummary']['StreamARN']

    enable = ddb.enable_kinesis_streaming_destination(
        TableName=t,
        StreamArn=stream_arn,
        EnableKinesisStreamingConfiguration={'ApproximateCreationDateTimePrecision': 'MICROSECOND'},
    )
    assert enable['DestinationStatus'] == 'ENABLING', (
        f"expected ENABLING immediately after EnableKinesisStreamingDestination, "
        f"got {enable['DestinationStatus']!r}"
    )

    active_dests = _poll_until(
        lambda: ddb.describe_kinesis_streaming_destination(TableName=t)['KinesisDataStreamDestinations'],
        lambda dests: any(d['StreamArn'] == stream_arn and d['DestinationStatus'] == 'ACTIVE' for d in dests),
        timeout_s=90,
        interval_s=2.0,
        description='kinesis streaming destination ACTIVE',
    )
    dest = next(d for d in active_dests if d['StreamArn'] == stream_arn)
    assert dest['DestinationStatus'] == 'ACTIVE', (
        f"expected ACTIVE destination for {stream_arn}, got {dest['DestinationStatus']!r}"
    )

    update = ddb.update_kinesis_streaming_destination(
        TableName=t,
        StreamArn=stream_arn,
        UpdateKinesisStreamingConfiguration={'ApproximateCreationDateTimePrecision': 'MILLISECOND'},
    )
    assert update['DestinationStatus'] == 'UPDATING', (
        f"expected UPDATING immediately after UpdateKinesisStreamingDestination, "
        f"got {update['DestinationStatus']!r}"
    )

    # Let the precision update settle back to ACTIVE before disabling.
    updated_dests = _poll_until(
        lambda: ddb.describe_kinesis_streaming_destination(TableName=t)['KinesisDataStreamDestinations'],
        lambda dests: any(d['StreamArn'] == stream_arn and d['DestinationStatus'] == 'ACTIVE' for d in dests),
        timeout_s=240,
        interval_s=3.0,
        description='kinesis streaming destination ACTIVE after update',
    )
    updated_dest = next(d for d in updated_dests if d['StreamArn'] == stream_arn)
    assert updated_dest.get('ApproximateCreationDateTimePrecision') == 'MILLISECOND', (
        f"expected the settled destination to carry precision MILLISECOND, got {updated_dest!r}"
    )

    disable = ddb.disable_kinesis_streaming_destination(TableName=t, StreamArn=stream_arn)
    assert disable['DestinationStatus'] == 'DISABLING', (
        f"expected DISABLING immediately after DisableKinesisStreamingDestination, "
        f"got {disable['DestinationStatus']!r}"
    )

    disabled_dests = _poll_until(
        lambda: ddb.describe_kinesis_streaming_destination(TableName=t)['KinesisDataStreamDestinations'],
        lambda dests: any(d['StreamArn'] == stream_arn and d['DestinationStatus'] == 'DISABLED' for d in dests),
        timeout_s=90,
        interval_s=2.0,
        description='kinesis streaming destination DISABLED',
    )
    disabled_dest = next(d for d in disabled_dests if d['StreamArn'] == stream_arn)
    assert disabled_dest['DestinationStatus'] == 'DISABLED', (
        f"expected DISABLED destination for {stream_arn}, got {disabled_dest['DestinationStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
