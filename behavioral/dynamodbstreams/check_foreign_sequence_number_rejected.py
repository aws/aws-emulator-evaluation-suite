"""foreign-sequence-number-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "foreign-sequence-number-rejected"
GROUP = "rejection"
SERVICES = ["dynamodbstreams"]

_ZERO_SEQUENCE = "0" * 21


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """GetShardIterator rejects AT_SEQUENCE_NUMBER with a sequence number foreign to the shard or
    none at all (ValidationException), while the shard's own sequence number reads its record.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_streams_GetShardIterator.html
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table, stream_arn = _create_stream_table(ctx, ddb, "NEW_IMAGE", "sim2real-behav-dbsseq-")
    _desc, shard_ids, _iterators = _wait_stream_usable(streams, stream_arn)

    key = {"pk": {"S": "sequence-item"}}
    ddb.put_item(TableName=table, Item={**key, "v": {"N": "7"}})
    holder, own_sequence = _shard_and_sequence_for(streams, stream_arn, shard_ids, key)

    # The Smithy model does not list ValidationException for GetShardIterator; AWS returns it.
    code, message = _error(lambda: streams.get_shard_iterator(
        StreamArn=stream_arn, ShardId=holder,
        ShardIteratorType="AT_SEQUENCE_NUMBER", SequenceNumber=_ZERO_SEQUENCE))
    assert code == "ValidationException", (
        f"AT_SEQUENCE_NUMBER on a sequence number foreign to the shard must be "
        f"ValidationException, got {code!r}"
    )
    assert message == "Invalid SequenceNumber for the shard", (
        f"AT_SEQUENCE_NUMBER on a foreign sequence number answered message {message!r}"
    )

    code, message = _error(lambda: streams.get_shard_iterator(
        StreamArn=stream_arn, ShardId=holder, ShardIteratorType="AT_SEQUENCE_NUMBER"))
    assert code == "ValidationException", (
        f"AT_SEQUENCE_NUMBER with no SequenceNumber must be ValidationException, got {code!r}"
    )
    assert message == (
        "One or more parameter values were invalid: SequenceNumber cannot be null"
    ), f"AT_SEQUENCE_NUMBER with no SequenceNumber answered message {message!r}"

    # Effect absent: no iterator was issued, so nothing was positioned -- and the refusals did not
    # damage the shard, which still describes itself as open with its original start.
    shard = next(s for s in streams.describe_stream(
        StreamArn=stream_arn)["StreamDescription"]["Shards"] if s["ShardId"] == holder)
    assert "EndingSequenceNumber" not in shard["SequenceNumberRange"], (
        f"the refused iterator requests must not close the shard; range is "
        f"{shard['SequenceNumberRange']!r}"
    )
    assert int(own_sequence) >= int(shard["SequenceNumberRange"]["StartingSequenceNumber"]), (
        f"the record's own sequence number {own_sequence} must sit at or after its shard's "
        f"start {shard['SequenceNumberRange']['StartingSequenceNumber']}"
    )

    # Positive control: the shard's OWN sequence number is accepted and selects that record.
    cursor = streams.get_shard_iterator(
        StreamArn=stream_arn, ShardId=holder, ShardIteratorType="AT_SEQUENCE_NUMBER",
        SequenceNumber=own_sequence)["ShardIterator"]
    got = _drain(streams, [holder], [cursor], want=1)
    assert [rec["dynamodb"]["NewImage"]["v"]["N"] for _s, rec in got] == ["7"], (
        f"AT_SEQUENCE_NUMBER on the shard's own sequence number must return that record, got "
        f"{[rec['dynamodb'].get('NewImage') for _s, rec in got]!r}"
    )
    assert got[0][1]["dynamodb"]["SequenceNumber"] == own_sequence, (
        f"the record read back must be the one the sequence number named, got "
        f"{got[0][1]['dynamodb']['SequenceNumber']!r} vs {own_sequence!r}"
    )


def _shard_and_sequence_for(streams, stream_arn: str, shard_ids: list, key: dict,
                            timeout_s: float = 150.0) -> tuple[str, str]:
    """(shard_id, SequenceNumber) of the record for ``key``.

    Which shard a partition key lands on is not knowable in advance, so poll every shard.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for sid in shard_ids:
            cursor = streams.get_shard_iterator(
                StreamArn=stream_arn, ShardId=sid,
                ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
            for record in streams.get_records(ShardIterator=cursor).get("Records", []):
                if record["dynamodb"]["Keys"] == key:
                    return sid, record["dynamodb"]["SequenceNumber"]
        time.sleep(2.0)
    raise AssertionError(
        f"no shard of {stream_arn} delivered a record for {key!r} within {timeout_s}s"
    )


def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) a call raised. Raises if the call SUCCEEDS."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {result!r}"
    )


def _create_stream_table(ctx, ddb, view_type: str, prefix: str) -> tuple[str, str]:
    name = ctx.unique_name(prefix)
    created = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": view_type},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    stream_arn = created["TableDescription"]["LatestStreamArn"]
    assert stream_arn, (
        f"CreateTable with StreamEnabled must mint a LatestStreamArn, got "
        f"{created['TableDescription'].get('LatestStreamArn')!r}"
    )
    return name, stream_arn


def _wait_stream_usable(streams, stream_arn: str, timeout_s: float = 180.0):
    """Poll until DescribeStream reports shards AND every shard hands back an iterator.

    GetShardIterator can answer ResourceNotFoundException for a few seconds after the stream
    already reports ENABLED with shards.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = streams.describe_stream(StreamArn=stream_arn)["StreamDescription"]
        shard_ids = [s["ShardId"] for s in desc.get("Shards", [])]
        if shard_ids:
            try:
                iterators = [
                    streams.get_shard_iterator(
                        StreamArn=stream_arn, ShardId=sid,
                        ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
                    for sid in shard_ids
                ]
            except ClientError as exc:
                last = exc.response["Error"]["Code"]
                if last != "ResourceNotFoundException":
                    raise
            else:
                return desc, shard_ids, iterators
        else:
            last = f"{desc.get('StreamStatus')} with 0 shards"
        time.sleep(2.0)
    raise AssertionError(
        f"stream {stream_arn} never became readable within {timeout_s}s; last state {last!r}"
    )


def _drain(streams, shard_ids: list, iterators: list, *, want: int, timeout_s: float = 120.0):
    """Follow every shard's NextShardIterator chain until ``want`` records are collected."""
    tagged: list = []
    cursors = list(iterators)
    deadline = time.monotonic() + timeout_s
    while len(tagged) < want and time.monotonic() < deadline:
        progressed = False
        for i, cursor in enumerate(cursors):
            if cursor is None:
                continue
            resp = streams.get_records(ShardIterator=cursor)
            got = resp.get("Records", [])
            if got:
                tagged.extend((shard_ids[i], rec) for rec in got)
                progressed = True
            cursors[i] = resp.get("NextShardIterator")
        if len(tagged) >= want or not any(cursors):
            break
        if not progressed:
            time.sleep(2.0)
    return tagged


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
