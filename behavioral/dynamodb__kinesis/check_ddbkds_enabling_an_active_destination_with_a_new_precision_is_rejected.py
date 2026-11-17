"""ddbkds-enabling-an-active-destination-with-a-new-precision-is-rejected."""

from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ddbkds-enabling-an-active-destination-with-a-new-precision-is-rejected"
GROUP = "streaming-destination-rejections"
SERVICES = ["dynamodb", "kinesis"]


@tags("axis:rejection", "cap:c1", "concern:eventing", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Enabling the ACTIVE destination's own stream with a different precision is refused with
    ValidationException and its exact message, the destination keeps its original precision,
    and a table with no destination accepts the same stream.
    """
    tok = ctx.unique_name("sim2real-ddbkds-")
    table = _make_table(ctx, f"{tok}-table")
    fresh = _make_table(ctx, f"{tok}-fresh")
    arn = _make_stream(ctx, f"{tok}-cdc")
    _wait_tables(ctx, [table, fresh])
    ddb = ctx.client("dynamodb")
    ddb.enable_kinesis_streaming_destination(
        TableName=table, StreamArn=arn,
        EnableKinesisStreamingConfiguration={"ApproximateCreationDateTimePrecision": "MICROSECOND"})
    _settle(ctx, table, want={arn: "ACTIVE"})

    code, message = _error(lambda: ddb.enable_kinesis_streaming_destination(
        TableName=table, StreamArn=arn,
        EnableKinesisStreamingConfiguration={"ApproximateCreationDateTimePrecision": "MILLISECOND"}))
    assert code == "ValidationException", (
        f"enabling the ACTIVE stream with a different precision must be refused with "
        f"ValidationException, got {code!r}"
    )
    expected_message = (
        "Table is not in a valid state to enable Kinesis Streaming Destination: "
        "EnableKinesisStreamingDestination must be DISABLED or ENABLE_FAILED to perform "
        "ENABLE operation."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after = _settle(ctx, table, want={arn: "ACTIVE"})
    assert after[0].get("ApproximateCreationDateTimePrecision") == "MICROSECOND", (
        f"the refusal must leave the original MICROSECOND precision untouched, got {after[0]!r}"
    )

    resp = ddb.enable_kinesis_streaming_destination(
        TableName=fresh, StreamArn=arn,
        EnableKinesisStreamingConfiguration={"ApproximateCreationDateTimePrecision": "MILLISECOND"})
    assert resp["DestinationStatus"] == "ENABLING", (
        f"positive control: a table with no destination must accept {arn!r}, got {resp!r}"
    )


_STATUS_DEADLINE_S = 600
_SETTLED = ("ACTIVE", "DISABLED", "ENABLE_FAILED")


def _poll(probe, predicate, *, timeout_s=120.0, interval_s=3.0, description="condition"):
    """Poll probe() until predicate(result) holds; RAISES on timeout, never returns a stale value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) fn() raises. RAISES when the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"the call succeeded; real AWS rejects it. It returned {result!r}")


def _make_table(ctx, name: str, *, region: str | None = None) -> str:
    """A minimal on-demand table, its delete registered before anything can fail."""
    ddb = ctx.client("dynamodb", region=region)
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ctx.client("dynamodb", region=region).delete_table(TableName=name))
    return name


def _wait_tables(ctx, names, *, region: str | None = None) -> None:
    ddb = ctx.client("dynamodb", region=region)
    for name in names:
        status = _poll(lambda n=name: ddb.describe_table(TableName=n)["Table"]["TableStatus"],
                       lambda s: s == "ACTIVE", timeout_s=180.0,
                       description=f"table {name} ACTIVE")
        assert status == "ACTIVE", f"table {name} is {status!r}"


def _make_stream(ctx, name: str, *, region: str | None = None) -> str:
    """A one-shard Kinesis data stream, deleted at teardown. Returns its ARN once ACTIVE."""
    kin = ctx.client("kinesis", region=region)
    kin.create_stream(StreamName=name, ShardCount=1, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: ctx.client("kinesis", region=region).delete_stream(
        StreamName=name, EnforceConsumerDeletion=True))
    summary = _poll(
        lambda: kin.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE", timeout_s=180.0,
        description=f"stream {name} ACTIVE")
    return summary["StreamARN"]


def _destinations(ctx, table: str, *, region: str | None = None) -> list:
    return ctx.client("dynamodb", region=region).describe_kinesis_streaming_destination(
        TableName=table)["KinesisDataStreamDestinations"]


def _settle(ctx, table: str, *, region: str | None = None, want: dict | None = None) -> list:
    """Poll until every destination on `table` is in a settled status (and, given `want`, until the
    {StreamArn: status} map equals it). DescribeKinesisStreamingDestination is eventually
    consistent -- it was measured still answering ACTIVE straight after a Disable returned
    DISABLING -- so the first read after a transition is never the one asserted."""
    def ok(dests):
        if any(d["DestinationStatus"] not in _SETTLED for d in dests):
            return False
        return want is None or {d["StreamArn"]: d["DestinationStatus"] for d in dests} == want
    return _poll(lambda: _destinations(ctx, table, region=region), ok,
                 timeout_s=float(_STATUS_DEADLINE_S), interval_s=5.0,
                 description=f"the streaming destinations on {table} settle"
                             + (f" to {want!r}" if want is not None else ""))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
