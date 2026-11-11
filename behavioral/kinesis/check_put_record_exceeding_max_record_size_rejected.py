"""put-record-exceeding-max-record-size-rejected."""
from __future__ import annotations

import hashlib
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")


def _register_stream_teardown(ctx, c, name, timeout_s=300, interval_s=5):
    def _teardown():
        deadline = time.monotonic() + timeout_s
        last = None
        deleted = False
        while time.monotonic() < deadline:
            try:
                c.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
                deleted = True
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ResourceInUseException", "LimitExceededException"):
                    raise
                last = code
                time.sleep(interval_s)
        if not deleted:
            raise AssertionError(
                f"stream {name} never reached a deletable state within {timeout_s}s "
                f"(last error {last}); it is still billing shard-hours"
            )
        while time.monotonic() < deadline:
            try:
                c.describe_stream_summary(StreamName=name)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return
                raise
            time.sleep(interval_s)
        raise AssertionError(
            f"stream {name} is still describable {timeout_s}s after DeleteStream returned; leak"
        )

    ctx.on_cleanup(_teardown)


def _wait_stream_active(c, name, timeout_s=180, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )


def _wait_stream_ready(c, name, timeout_s=180):
    _wait_stream_active(c, name, timeout_s=timeout_s)

    def _shards():
        try:
            return c.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "ResourceInUseException", "ResourceNotFoundException",
            ):
                return None
            raise

    _poll(_shards, lambda shards: bool(shards), 120, 2, f"stream {name} shards addressable")


def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(
        c, name, ShardCount=shard_count, StreamModeDetails={"StreamMode": "PROVISIONED"}
    )
    _register_stream_teardown(ctx, c, name)
    _wait_stream_ready(c, name)
    return name


def _shard_ids(c, name):
    return [s["ShardId"] for s in c.list_shards(StreamName=name)["Shards"]]


def _call_when_ready(fn, timeout_s=120, interval_s=2):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("ResourceNotFoundException", "ResourceInUseException") or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _drain(c, iterator, want, timeout_s=180, interval_s=1.0, limit=1000):
    """Collect at least ``want`` records, chaining NextShardIterator across EMPTY pages."""
    collected = []
    pages = 0
    deadline = time.monotonic() + timeout_s
    while True:
        resp = c.get_records(ShardIterator=iterator, Limit=limit)
        pages += 1
        collected.extend(resp.get("Records", []))
        nxt = resp.get("NextShardIterator")
        if nxt is None:
            return collected, None, pages
        iterator = nxt
        if len(collected) >= want:
            return collected, iterator, pages
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"drained {pages} GetRecords pages over {timeout_s}s and saw "
                f"{len(collected)} of {want} expected records with sizes "
                f"{[len(bytes(r['Data'])) for r in collected]}"
            )
        time.sleep(interval_s)


def _digest(blob):
    """Short identity for a payload too large to put in an assertion message."""
    return f"{len(blob)}B/sha256:{hashlib.sha256(blob).hexdigest()[:16]}"


CHECK = "put-record-exceeding-max-record-size-rejected"
GROUP = 'data-plane'
SERVICES = ['kinesis']


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecord accepts Data of exactly 1 MiB and refuses one byte more with ValidationException,
    storing nothing; the stream stays writable afterwards.

    Reference: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecord.html
    """
    c = ctx.client("kinesis")
    one_mib = 1024 * 1024
    # Enforced by the front-end request validator, not the modeled InvalidArgumentException; the
    # Smithy model's Data max is 10 MiB, so botocore cannot pre-empt it. The stream is at the
    # default size (UpdateMaxRecordSize is never called).
    expected_code = "ValidationException"

    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _shard_ids(c, name)[0]

    # Control: Data of EXACTLY the limit succeeds and is readable. Using the boundary value
    # itself (rather than a comfortable margin) is what makes the refusal below attributable to
    # one byte of Data and nothing else.
    under = b"u" * one_mib
    put_ok = _call_when_ready(
        lambda: c.put_record(StreamName=name, Data=under, PartitionKey="k")
    )
    assert put_ok["ShardId"] == shard_id, (
        f"the under-limit record landed on {put_ok['ShardId']}, not the only shard {shard_id}"
    )

    # Break exactly one thing: the same call, ONE byte over the limit.
    over = b"o" * (one_mib + 1)
    try:
        c.put_record(StreamName=name, Data=over, PartitionKey="k")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == expected_code, (
            f"PutRecord with a {len(over)}-byte Data blob ({_digest(over)}) failed with "
            f"{code}; real AWS answers {expected_code}. The at-limit control of "
            f"{len(under)} bytes succeeded, so this is the size boundary and not a broken stream"
        )
        message = exc.response.get("Error", {}).get("Message")
        assert message == (
            "1 validation error detected: Value at 'data' failed to satisfy constraint: "
            "Member must have length less than or equal to 1048576"
        ), f"PutRecord oversized-record message: {message!r}"
    else:
        raise AssertionError(
            f"PutRecord ACCEPTED a {len(over)}-byte Data blob ({_digest(over)}); real AWS "
            f"caps a record at exactly {one_mib} bytes of Data. This is the over-permissive direction: the "
            f"Smithy model's Data max is 10485760, so an emulator validating against the "
            f"model instead of the service limit lands exactly here"
        )

    # Effect absent: the oversized record was not stored; the shard holds only the control.
    it = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    recs, _next_it, pages = _drain(c, it, want=1)
    sizes = [len(bytes(r["Data"])) for r in recs]
    assert len(recs) == 1, (
        f"expected exactly the one accepted record on the shard after the refusal, found "
        f"{len(recs)} with sizes {sizes} over {pages} pages"
    )
    stored = bytes(recs[0]["Data"])
    assert stored == under, (
        f"read back {_digest(stored)}, expected the control payload {_digest(under)}"
    )
    assert stored != over, f"the refused oversized payload {_digest(over)} was stored anyway"

    # Control still works after the refusal, and the effect is independently observable —
    # not just echoed back in the mutating call's own response.
    tail = _call_when_ready(
        lambda: c.put_record(StreamName=name, Data=b"still-writable", PartitionKey="k")
    )
    assert int(tail["SequenceNumber"]) > int(put_ok["SequenceNumber"]), (
        f"post-refusal PutRecord returned sequence number {tail['SequenceNumber']}, which "
        f"does not advance past {put_ok['SequenceNumber']}"
    )
    it2 = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    final_recs, _next_it2, final_pages = _drain(c, it2, want=2)
    final_sizes = [len(bytes(r["Data"])) for r in final_recs]
    assert len(final_recs) == 2, (
        f"expected exactly 2 records on the shard (the under-limit control plus the "
        f"post-refusal tail) after the refusal, found {len(final_recs)} with sizes "
        f"{final_sizes} over {final_pages} pages"
    )
    assert bytes(final_recs[1]["Data"]) == b"still-writable", (
        f"the post-refusal record read back {_digest(bytes(final_recs[1]['Data']))}, expected "
        f"the literal tail payload b'still-writable'"
    )
    assert final_recs[1]["SequenceNumber"] == tail["SequenceNumber"], (
        f"the independently-read tail record's sequence number "
        f"{final_recs[1]['SequenceNumber']} does not match the one PutRecord returned "
        f"{tail['SequenceNumber']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
