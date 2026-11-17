"""ddbkds-same-stream-re-enabled-after-disable-settles-on-the-new-precision."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "ddbkds-same-stream-re-enabled-after-disable-settles-on-the-new-precision"
GROUP = "streaming-destination-config"
SERVICES = ["dynamodb", "kinesis"]

_DELIVERY_DEADLINE_S = 180
#: Runner-to-AWS clock skew allowance; the units differ by 1000x, so this never blurs them.
_SKEW_S = 300


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A stream disabled to DISABLED and re-enabled with a different precision lists that stream
    ARN exactly once, ACTIVE, on the new precision, and a write after it is stamped in that unit.
    """
    tok = ctx.unique_name("sim2real-ddbkds-")
    table = _make_table(ctx, f"{tok}-table")
    stream = f"{tok}-cdc"
    arn = _make_stream(ctx, stream)
    _wait_tables(ctx, [table])
    ddb = ctx.client("dynamodb")

    ddb.enable_kinesis_streaming_destination(
        TableName=table, StreamArn=arn,
        EnableKinesisStreamingConfiguration={"ApproximateCreationDateTimePrecision": "MICROSECOND"})
    first = _settle(ctx, table, want={arn: "ACTIVE"})[0]
    assert first.get("ApproximateCreationDateTimePrecision") == "MICROSECOND", (
        f"the first ACTIVE destination must describe MICROSECOND, got {first!r}"
    )

    ddb.disable_kinesis_streaming_destination(TableName=table, StreamArn=arn)
    _settle(ctx, table, want={arn: "DISABLED"})

    ddb.enable_kinesis_streaming_destination(
        TableName=table, StreamArn=arn,
        EnableKinesisStreamingConfiguration={"ApproximateCreationDateTimePrecision": "MILLISECOND"})
    after = _settle(ctx, table, want={arn: "ACTIVE"})
    assert [d["StreamArn"] for d in after] == [arn], (
        f"the re-enabled stream must be listed exactly once, got {after!r}"
    )
    assert after[0].get("ApproximateCreationDateTimePrecision") == "MILLISECOND", (
        f"the re-enabled destination must describe MILLISECOND, got {after[0]!r}"
    )

    shard = _Shard(ctx, stream)
    t0 = time.time()
    ddb.put_item(TableName=table, Item={"id": {"S": "after-reenable"}})
    t1 = time.time()
    got, low, high = _stamp(shard.record_for(table, "after-reenable"), t0, t1, 1_000)
    assert low <= got <= high, (
        f"the write after the re-enable is stamped {got}, not epoch milliseconds in [{low}, {high}]"
    )


class _Shard:
    """A TRIM_HORIZON reader over a one-shard stream that accumulates every decoded record."""

    def __init__(self, ctx, stream: str) -> None:
        self._kin = ctx.client("kinesis")
        shards = self._kin.list_shards(StreamName=stream)["Shards"]
        assert len(shards) == 1, f"the one-shard stream lists {len(shards)} shards: {shards!r}"
        self._cursor = self._kin.get_shard_iterator(
            StreamName=stream, ShardId=shards[0]["ShardId"],
            ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
        self.records: list[dict] = []

    def _read(self) -> list[dict]:
        page = self._kin.get_records(ShardIterator=self._cursor, Limit=100)
        self._cursor = page["NextShardIterator"]
        self.records.extend(json.loads(r["Data"]) for r in page["Records"])
        return list(self.records)

    def record_for(self, table: str, key: str) -> dict:
        """The one change record for item ``key`` of ``table``, polled to the delivery deadline."""
        def mine(rs):
            return [r for r in rs if r.get("tableName") == table
                    and r.get("dynamodb", {}).get("Keys") == {"id": {"S": key}}]
        found = mine(_poll(self._read, lambda rs: bool(mine(rs)), timeout_s=float(_DELIVERY_DEADLINE_S),
                           interval_s=2.0, description=f"the change record for {table}/{key}"))
        assert len({r.get("eventID") for r in found}) == 1, (
            f"one PutItem on {table}/{key} produced {len(found)} distinct events: {found!r}")
        return found[0]


def _stamp(rec: dict, t0: float, t1: float, per_second: int) -> tuple[int, int, int]:
    """(ApproximateCreationDateTime, low, high): the write's wall-clock bracket in ticks of
    ``per_second``, widened by a clock-skew allowance far below the 1000x step between units."""
    value = int(rec["dynamodb"]["ApproximateCreationDateTime"])
    return value, int((t0 - _SKEW_S) * per_second), int((t1 + _SKEW_S) * per_second)


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
