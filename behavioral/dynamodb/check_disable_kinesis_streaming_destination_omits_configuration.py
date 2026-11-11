"""disable-kinesis-streaming-destination-omits-configuration."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disable-kinesis-streaming-destination-omits-configuration"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableKinesisStreamingDestination returns only TableName, StreamArn and DestinationStatus.

    Unlike Enable, it does not echo EnableKinesisStreamingConfiguration, even for a destination
    enabled with an explicit precision.
    """
    ddb = ctx.client("dynamodb")
    kinesis = ctx.client("kinesis")

    stream_name = ctx.unique_name("sim2real-behav-kds-")
    kinesis.create_stream(StreamName=stream_name, StreamModeDetails={"StreamMode": "ON_DEMAND"},
                          Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _safe_delete_stream(kinesis, stream_name))
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )

    enabled = ddb.enable_kinesis_streaming_destination(
        TableName=table_name,
        StreamArn=stream_arn,
        EnableKinesisStreamingConfiguration={"ApproximateCreationDateTimePrecision": "MICROSECOND"},
    )
    # Positive control: Enable's own response DOES echo the configuration -- so Disable's
    # omission below is specific to Disable, not a blanket absence of the field.
    assert enabled["EnableKinesisStreamingConfiguration"]["ApproximateCreationDateTimePrecision"] == "MICROSECOND", (
        f"positive control: expected Enable's response to echo the requested precision, got {enabled!r}"
    )

    active = _poll_until(
        lambda: _destination_for(ddb, table_name, stream_arn),
        lambda dest: dest["DestinationStatus"] == "ACTIVE",
        timeout_s=240,
        interval_s=5,
    )
    assert active.get("ApproximateCreationDateTimePrecision") == "MICROSECOND", (
        f"expected the ACTIVE destination to report the enabled precision, got {active!r}"
    )

    disabled = ddb.disable_kinesis_streaming_destination(TableName=table_name, StreamArn=stream_arn)
    assert disabled["DestinationStatus"] in ("DISABLING", "DISABLED"), (
        f"expected DISABLING or DISABLED immediately after Disable, got {disabled['DestinationStatus']!r}"
    )
    assert "EnableKinesisStreamingConfiguration" not in disabled, (
        "expected DisableKinesisStreamingDestination's response to omit "
        f"EnableKinesisStreamingConfiguration, got {disabled!r}"
    )
    assert disabled["TableName"] == table_name and disabled["StreamArn"] == stream_arn, (
        f"expected Disable's response to still echo TableName/StreamArn, got {disabled!r}"
    )

    final = _poll_until(
        lambda: _destination_for(ddb, table_name, stream_arn),
        lambda dest: dest["DestinationStatus"] == "DISABLED",
        timeout_s=180,
        interval_s=5,
    )
    assert final["DestinationStatus"] == "DISABLED", (
        f"expected the destination to settle at DISABLED, got {final['DestinationStatus']!r}"
    )


def _destination_for(ddb: Any, table_name: str, stream_arn: str) -> dict[str, Any]:
    resp = ddb.describe_kinesis_streaming_destination(TableName=table_name)
    for dest in resp.get("KinesisDataStreamDestinations", []):
        if dest["StreamArn"] == stream_arn:
            return dest
    raise AssertionError(f"stream {stream_arn} missing from destinations: {resp}")


def _safe_delete_stream(kinesis: Any, stream_name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_table(ddb: Any, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
