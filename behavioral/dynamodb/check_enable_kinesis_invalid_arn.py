"""enable-kinesis-invalid-arn."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enable-kinesis-invalid-arn"
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


def _destination_for(ddb, table_name, stream_arn):
    resp = ddb.describe_kinesis_streaming_destination(TableName=table_name)
    for dest in resp.get('KinesisDataStreamDestinations', []):
        if dest['StreamArn'] == stream_arn:
            return dest
    return None


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableKinesisStreamingDestination accepts a well-formed ARN of a nonexistent stream, but the
    destination settles in ENABLE_FAILED, never ACTIVE; a control on a real stream reaches ACTIVE.
    """
    ddb = ctx.client('dynamodb')
    kinesis = ctx.client('kinesis')

    stream_name = ctx.unique_name('sim2real-behav-kia-')
    kinesis.create_stream(StreamName=stream_name, StreamModeDetails={'StreamMode': 'ON_DEMAND'})
    ctx.on_cleanup(lambda: _delete_stream_ignore(kinesis, stream_name))
    real_stream_arn = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=stream_name)['StreamDescriptionSummary'],
        lambda d: d['StreamStatus'] == 'ACTIVE',
        timeout_s=120,
        interval_s=3.0,
        description='positive-control kinesis stream ACTIVE',
    )['StreamARN']

    t_control = ctx.unique_name('sim2real-behav-kia-ctl-')
    ddb.create_table(TableName=t_control, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t_control))
    ddb.get_waiter('table_exists').wait(TableName=t_control, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    control_resp = ddb.enable_kinesis_streaming_destination(TableName=t_control, StreamArn=real_stream_arn)
    assert control_resp['DestinationStatus'] in ('ENABLING', 'ACTIVE'), control_resp
    control_final = _poll_until(
        lambda: _destination_for(ddb, t_control, real_stream_arn),
        lambda d: d is not None and d['DestinationStatus'] == 'ACTIVE',
        timeout_s=180,
        interval_s=3.0,
        description='positive-control kinesis streaming destination reaches ACTIVE',
    )
    assert control_final['DestinationStatus'] == 'ACTIVE', (
        f'positive control must reach ACTIVE for a real, existing stream: {control_final}'
    )

    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    account_id = ddb.describe_table(TableName=t)['Table']['TableArn'].split(':')[4]
    bogus_stream_arn = f"arn:aws:kinesis:{ctx.region}:{account_id}:stream/{ctx.unique_name('no-such-stream-')}"

    # AWS accepts the well-formed ARN synchronously; a target that rejects it here diverges.
    enable_resp = ddb.enable_kinesis_streaming_destination(TableName=t, StreamArn=bogus_stream_arn)
    assert enable_resp['DestinationStatus'] in ('ENABLING', 'ENABLE_FAILED'), enable_resp

    final = _poll_until(
        lambda: _destination_for(ddb, t, bogus_stream_arn),
        lambda d: d is not None and d['DestinationStatus'] in ('ENABLE_FAILED', 'ACTIVE'),
        timeout_s=180,
        interval_s=3.0,
        description='kinesis streaming destination for a nonexistent stream settles',
    )
    assert final['DestinationStatus'] == 'ENABLE_FAILED', (
        f'a destination pointed at a nonexistent Kinesis stream must never reach ACTIVE: {final}'
    )


def _delete_stream_ignore(kinesis, stream_name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
