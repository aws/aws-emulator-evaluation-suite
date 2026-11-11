"""deep-kinesis-resharding-update-shard-count-below-half-rejected."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-kinesis-resharding-update-shard-count-below-half-rejected"
GROUP = 'resharding'
SERVICES = ['kinesis']

MAX_HASH = 2 ** 128 - 1


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _md5(key: str) -> int:
    return int(hashlib.md5(key.encode()).hexdigest(), 16)


def _range(shard: dict) -> tuple[int, int]:
    return (int(shard["HashKeyRange"]["StartingHashKey"]),
            int(shard["HashKeyRange"]["EndingHashKey"]))


def _is_open(shard: dict) -> bool:
    return "EndingSequenceNumber" not in shard["SequenceNumberRange"]


def _register_stream_teardown(ctx, c, name, timeout_s=300, interval_s=5):
    """Delete the stream at teardown and prove it is gone.

    DeleteStream is refused with ResourceInUseException while the stream is UPDATING.
    """

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
        raise AssertionError(f"stream {name} still describable {timeout_s}s after DeleteStream")

    ctx.on_cleanup(_teardown)


def _await_ready(c, name, timeout_s=240):
    """Wait until ACTIVE per DescribeStreamSummary AND listable: the summary flips first."""
    def probe():
        s = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if s["StreamStatus"] != "ACTIVE":
            return s["StreamStatus"]
        try:
            c.list_shards(StreamName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceInUseException":
                return "ACTIVE-but-unlistable"
            raise
        return "READY"
    _poll(probe, lambda st: st == "READY", timeout_s, 2, f"stream {name} ACTIVE and listable")


def _await_topology(c, name, pred, description, timeout_s=240):
    """Poll until the stream is ready AND its shard map satisfies ``pred``; return the map.

    The summary can still read ACTIVE right after a reshard call, before the stream is UPDATING.
    """
    def probe():
        _await_ready(c, name, timeout_s)
        return _list_shards(c, name)
    return _poll(probe, pred, timeout_s, 2, description)


def _create_stream(ctx, c, shard_count):
    name = ctx.unique_name("sim2real-behav-kre-")
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, ShardCount=shard_count,
                            StreamModeDetails={"StreamMode": "PROVISIONED"},
                            Tags={"sim2real": "deep-kinesis-resharding"})
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            time.sleep(min(5 + attempt * 2, 15))
    else:
        raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}")
    _register_stream_teardown(ctx, c, name)
    _await_ready(c, name)
    return name


def _list_shards(c, name):
    out, token = [], None
    while True:
        resp = c.list_shards(**({"NextToken": token} if token else {"StreamName": name}))
        out += resp["Shards"]
        token = resp.get("NextToken")
        if not token:
            return out


def _drain_closed(c, name, shard_id, max_pages=400):
    """Read a CLOSED shard to its end: the page with no NextShardIterator. Returns (records, final)."""
    it = c.get_shard_iterator(StreamName=name, ShardId=shard_id,
                              ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    records = []
    for _ in range(max_pages):
        resp = c.get_records(ShardIterator=it, Limit=1000)
        records += resp["Records"]
        it = resp.get("NextShardIterator")
        if it is None:
            return records, resp
        time.sleep(0.25)
    raise AssertionError(f"closed shard {shard_id} never returned a null NextShardIterator "
                         f"in {max_pages} pages; read {len(records)} records")


def _drain_open(c, name, shard_id, want, timeout_s=120):
    """Read an OPEN shard until ``want`` records are in hand and a caught-up empty page follows."""
    it = c.get_shard_iterator(StreamName=name, ShardId=shard_id,
                              ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    records = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = c.get_records(ShardIterator=it, Limit=1000)
        records += resp["Records"]
        it = resp["NextShardIterator"]
        if (len(records) >= want and not resp["Records"]
                and resp.get("MillisBehindLatest", 1) == 0):
            return records
        time.sleep(0.5)
    raise AssertionError(f"open shard {shard_id} served {len(records)} of {want} expected "
                         f"records within {timeout_s}s")


def _put_until_open(c, name, key, closed_ids, tag, writes, timeout_s=180):
    """PutRecord ``key`` until the service routes it to an OPEN shard; log every write.

    Routing leaves a split parent ~20 s after the stream is ACTIVE; earlier writes land in the parent.
    """
    deadline = time.monotonic() + timeout_s
    n = 0
    while True:
        data = f"{tag}-{n}"
        resp = c.put_record(StreamName=name, PartitionKey=key, Data=data.encode())
        writes.append((key, data, resp["ShardId"]))
        if resp["ShardId"] not in closed_ids:
            return resp
        if time.monotonic() >= deadline:
            raise AssertionError(f"PutRecord({key!r}) was still routed to closed shard "
                                 f"{resp['ShardId']} {timeout_s}s after the reshard landed")
        n += 1
        time.sleep(1)


def _refusal(fn):
    """Exact error code and message of a call that MUST be refused. A success is a failure."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED: {resp!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateShardCount below half the open shard count (4 -> 1) is an InvalidArgumentException.

    All four shards stay open and untouched, and exactly half (4 -> 2) then succeeds.
    """
    c = ctx.client("kinesis")
    name = _create_stream(ctx, c, 4)
    before = sorted(_list_shards(c, name), key=lambda s: _range(s)[0])
    snapshot = [(s["ShardId"], _range(s), _is_open(s)) for s in before]
    assert len(before) == 4 and all(o for _i, _r, o in snapshot), f"setup: expected 4 open shards: {snapshot!r}"

    code, message = _refusal(lambda: c.update_shard_count(
        StreamName=name, TargetShardCount=1, ScalingType="UNIFORM_SCALING"))
    assert code == "InvalidArgumentException", (
        f"UpdateShardCount 4 -> 1 (below half) returned {code!r}, expected InvalidArgumentException"
    )
    expected = (
        "UpdateShardCount cannot scale down below half your current open shard count. "
        "Current open shard count: 4 Target shard count: 1"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # ---- effect absent -------------------------------------------------------------------- #
    summary = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert summary["StreamStatus"] == "ACTIVE", (
        f"the refused UpdateShardCount left the stream {summary['StreamStatus']!r}"
    )
    assert summary["OpenShardCount"] == 4, f"OpenShardCount is {summary['OpenShardCount']!r} after the refusal"
    after = sorted(_list_shards(c, name), key=lambda s: _range(s)[0])
    assert [(s["ShardId"], _range(s), _is_open(s)) for s in after] == snapshot, (
        f"the shard map changed after a refused UpdateShardCount: before {snapshot!r}, "
        f"after {[(s['ShardId'], _range(s), _is_open(s)) for s in after]!r}"
    )

    # ---- positive control: exactly half is allowed on the same stream -------------------- #
    ok = c.update_shard_count(StreamName=name, TargetShardCount=2, ScalingType="UNIFORM_SCALING")
    assert (ok["CurrentShardCount"], ok["TargetShardCount"]) == (4, 2), (
        f"UpdateShardCount 4 -> 2 echoed {ok['CurrentShardCount']!r} -> {ok['TargetShardCount']!r}"
    )
    _await_topology(c, name, lambda sh: sum(1 for s in sh if _is_open(s)) == 2, "2 open shards in ListShards")
    summary = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert summary["OpenShardCount"] == 2, (
        f"after the allowed 4 -> 2, OpenShardCount is {summary['OpenShardCount']!r}"
    )
    by_id = {s["ShardId"]: s for s in _list_shards(c, name)}
    assert all(not _is_open(by_id[i]) for i, _r, _o in snapshot), (
        "after halving to 2, one of the original four shards is still open"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
