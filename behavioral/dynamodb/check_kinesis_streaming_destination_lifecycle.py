"""kinesis-streaming-destination-lifecycle."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-streaming-destination-lifecycle"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Enabling, updating (MICROSECOND precision) and disabling a Kinesis streaming destination
    moves DestinationStatus to ACTIVE, back to ACTIVE, then DISABLED, and the disabled
    destination stays listed in DescribeKinesisStreamingDestination."""
    ddb = ctx.client("dynamodb")
    kinesis = ctx.client("kinesis")

    stream_name = ctx.unique_name("sim2real-behav-kds-")
    kinesis.create_stream(StreamName=stream_name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: _delete_stream_ignore(kinesis, stream_name))
    stream_arn = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"],
        lambda d: d["StreamStatus"] == "ACTIVE",
        timeout_s=180,
        interval_s=5,
    )["StreamARN"]

    table_name = ctx.unique_name("sim2real-behav-kds-tbl-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, table_name))
    _wait_table_active(ddb, table_name)

    enabled = ddb.enable_kinesis_streaming_destination(TableName=table_name, StreamArn=stream_arn)
    assert enabled["DestinationStatus"] in ("ENABLING", "ACTIVE")

    active_dest = _poll_until(
        lambda: _get_destination(ddb, table_name, stream_arn),
        lambda d: d is not None and d["DestinationStatus"] == "ACTIVE",
        timeout_s=180,
        interval_s=5,
    )
    assert active_dest["StreamArn"] == stream_arn

    updated = ddb.update_kinesis_streaming_destination(
        TableName=table_name,
        StreamArn=stream_arn,
        UpdateKinesisStreamingConfiguration={"ApproximateCreationDateTimePrecision": "MICROSECOND"},
    )
    assert updated["DestinationStatus"] in ("UPDATING", "ACTIVE")

    # Settling UPDATING back to ACTIVE can take well over 120s.
    settled = _poll_until(
        lambda: _get_destination(ddb, table_name, stream_arn),
        lambda d: d is not None and d["DestinationStatus"] == "ACTIVE",
        timeout_s=300,
        interval_s=5,
    )
    assert settled["ApproximateCreationDateTimePrecision"] == "MICROSECOND"

    disabled = ddb.disable_kinesis_streaming_destination(TableName=table_name, StreamArn=stream_arn)
    assert disabled["DestinationStatus"] in ("DISABLING", "DISABLED")

    final_status = _poll_until(
        lambda: _get_destination(ddb, table_name, stream_arn),
        lambda d: d is None or d["DestinationStatus"] == "DISABLED",
        timeout_s=180,
        interval_s=5,
    )
    # A disabled destination stays listed as DISABLED rather than being dropped.
    assert final_status is not None, "destination disappeared from the list after disable"
    assert final_status["DestinationStatus"] == "DISABLED"


def _get_destination(ddb, table_name: str, stream_arn: str) -> dict | None:
    dests = ddb.describe_kinesis_streaming_destination(TableName=table_name)["KinesisDataStreamDestinations"]
    for d in dests:
        if d["StreamArn"] == stream_arn:
            return d
    return None


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _wait_table_active(ddb, table_name: str, timeout_s: float = 120) -> None:
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=3,
    )


def _delete_table_ignore(ddb, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _delete_stream_ignore(kinesis, stream_name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
