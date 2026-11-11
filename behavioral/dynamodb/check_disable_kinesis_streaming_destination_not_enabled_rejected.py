"""disable-kinesis-streaming-destination-not-enabled-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disable-kinesis-streaming-destination-not-enabled-rejected"
GROUP = "overly-permissive"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisableKinesisStreamingDestination for a never-enabled stream fails with ValidationException
    and leaves no destinations; enabling then disabling the same stream reaches DISABLED."""
    ddb = ctx.client("dynamodb")
    kinesis = ctx.client("kinesis")

    table_name = ctx.unique_name("sim2real-behav-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_status(ctx, table_name, "ACTIVE")

    stream_name = ctx.unique_name("sim2real-behav-stream-")
    kinesis.create_stream(
        StreamName=stream_name,
        ShardCount=1,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    stream_arn = _wait_stream_active(ctx, stream_name)

    # Never enabled on the table -> disabling it must fail, not silently succeed.
    code, message = _error(
        lambda: ddb.disable_kinesis_streaming_destination(
            TableName=table_name, StreamArn=stream_arn
        )
    )
    # Real AWS surfaces this as a generic parameter-validation error rather than the
    # ResourceNotFoundException shape one might expect for a "no such destination" case.
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        "Table is not in a valid state to enable Kinesis Streaming Destination: "
        "KinesisStreamingDestination must be ACTIVE to perform DISABLE operation."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    destinations = ddb.describe_kinesis_streaming_destination(TableName=table_name)[
        "KinesisDataStreamDestinations"
    ]
    assert destinations == [], f"expected no streaming destinations, found {destinations}"

    # Positive control: enable then disable the SAME stream succeeds and reaches DISABLED.
    ddb.enable_kinesis_streaming_destination(TableName=table_name, StreamArn=stream_arn)
    _wait_destination_status(ctx, table_name, stream_arn, "ACTIVE")

    disable_resp = ddb.disable_kinesis_streaming_destination(
        TableName=table_name, StreamArn=stream_arn
    )
    assert disable_resp["DestinationStatus"] in ("DISABLING", "DISABLED"), (
        f"expected DISABLING or DISABLED immediately after disabling an active destination, "
        f"got {disable_resp['DestinationStatus']!r}"
    )
    _wait_destination_status(ctx, table_name, stream_arn, "DISABLED")


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_table_status(ctx, table_name, target_status, timeout_s=180, interval_s=3):
    import time

    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        last = desc["TableStatus"]
        if last == target_status:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never reached {target_status}, last={last}")


def _wait_stream_active(ctx, stream_name, timeout_s=180, interval_s=3):
    import time

    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
        last = desc["StreamStatus"]
        if last == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(interval_s)
    raise AssertionError(f"stream {stream_name} never reached ACTIVE, last={last}")


def _wait_destination_status(ctx, table_name, stream_arn, target_status, timeout_s=180, interval_s=3):
    import time

    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        dests = ddb.describe_kinesis_streaming_destination(TableName=table_name)[
            "KinesisDataStreamDestinations"
        ]
        match = next((d for d in dests if d["StreamArn"] == stream_arn), None)
        last = match["DestinationStatus"] if match else "MISSING"
        if last == target_status:
            return match
        time.sleep(interval_s)
    raise AssertionError(f"destination for {stream_arn} never reached {target_status}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
