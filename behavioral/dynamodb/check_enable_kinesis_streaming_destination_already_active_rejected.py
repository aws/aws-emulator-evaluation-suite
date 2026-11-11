"""enable-kinesis-streaming-destination-already-active-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "enable-kinesis-streaming-destination-already-active-rejected"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-enabling an already-ACTIVE Kinesis streaming destination fails with ValidationException
    and leaves it ACTIVE; after a disable, re-enabling the same stream succeeds and reaches ACTIVE.
    """
    ddb = ctx.client("dynamodb")
    kinesis = ctx.client("kinesis")

    stream_name = ctx.unique_name("sim2real-behav-kdsrej-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: _safe_delete_stream(kinesis, stream_name))
    kinesis.add_tags_to_stream(StreamName=stream_name, Tags={"sim2real": CHECK})
    stream_arn = _poll_until(
        lambda: kinesis.describe_stream(StreamName=stream_name)["StreamDescription"],
        lambda desc: desc["StreamStatus"] == "ACTIVE",
        timeout_s=180,
        interval_s=5,
    )["StreamARN"]

    table_name = ctx.unique_name("sim2real-behav-kdsrej-tbl-")
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

    ddb.enable_kinesis_streaming_destination(TableName=table_name, StreamArn=stream_arn)
    _poll_until(
        lambda: _destination_status(ddb, table_name, stream_arn),
        lambda status: status == "ACTIVE",
        timeout_s=300,
        interval_s=5,
    )

    code, message = _error_code_and_message(
        lambda: ddb.enable_kinesis_streaming_destination(
            TableName=table_name, StreamArn=stream_arn
        )
    )
    # ValidationException, not ResourceInUseException (used for in-progress transitions).
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "Table is not in a valid state to enable Kinesis Streaming Destination: "
        "EnableKinesisStreamingDestination must be DISABLED or ENABLE_FAILED to perform "
        "ENABLE operation."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still_active = _destination_status(ddb, table_name, stream_arn)
    assert still_active == "ACTIVE", f"expected ACTIVE after rejected re-enable, got {still_active!r}"

    # The rejection is tied to the ACTIVE state, not a permanent block on the pair.
    ddb.disable_kinesis_streaming_destination(TableName=table_name, StreamArn=stream_arn)
    _poll_until(
        lambda: _destination_status(ddb, table_name, stream_arn),
        lambda status: status in (None, "DISABLED"),
        timeout_s=300,
        interval_s=5,
    )

    ddb.enable_kinesis_streaming_destination(TableName=table_name, StreamArn=stream_arn)
    restored = _poll_until(
        lambda: _destination_status(ddb, table_name, stream_arn),
        lambda status: status == "ACTIVE",
        timeout_s=300,
        interval_s=5,
    )
    assert restored == "ACTIVE", f"expected re-enable after disable to reach ACTIVE, got {restored!r}"


def _destination_status(ddb: Any, table_name: str, stream_arn: str) -> str | None:
    resp = ddb.describe_kinesis_streaming_destination(TableName=table_name)
    for dest in resp.get("KinesisDataStreamDestinations", []):
        if dest["StreamArn"] == stream_arn:
            return dest["DestinationStatus"]
    return None


def _error_code_and_message(fn: Callable[[], Any]) -> tuple[str | None, str | None]:
    """Return fn()'s error code and message; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response:
            err = response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError(
        f"real DynamoDB rejects re-enabling an already-ACTIVE destination, but it "
        f"SUCCEEDED and returned {result!r}"
    )


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
