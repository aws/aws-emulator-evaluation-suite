"""split-shard-new-starting-hash-key-outside-parent-range-rejected."""
from __future__ import annotations

import collections
import hashlib
import time

from behavioral_harness import tags

CHECK = "split-shard-new-starting-hash-key-outside-parent-range-rejected"
GROUP = 'resharding'
SERVICES = ['kinesis']

MAX_HASH = 2 ** 128 - 1
N_KEYS = 12
PER_KEY = 3


class _UnexpectedSuccess(Exception):
    """Raised when a SplitShard that AWS rejects is accepted."""


def _md5_int(key: str) -> int:
    return int(hashlib.md5(key.encode()).hexdigest(), 16)


def _client_error(fn, **kwargs) -> dict:
    """The AWS error (code and message), or a raise. Never a falsy sentinel on success."""
    try:
        resp = fn(**kwargs)
    except Exception as exc:  # noqa: BLE001 — the code is the assertion
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if not code:
            raise AssertionError(f"call raised {type(exc).__name__} with no AWS error code: {exc}") from exc
        return exc.response["Error"]
    raise _UnexpectedSuccess(f"SplitShard was ACCEPTED and returned {resp!r}")


def _list_shards(kin, name: str) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        resp = kin.list_shards(**({"NextToken": token} if token else {"StreamName": name}))
        out += resp["Shards"]
        token = resp.get("NextToken")
        if not token:
            return out


def _range(shard: dict) -> tuple[int, int]:
    return (int(shard["HashKeyRange"]["StartingHashKey"]),
            int(shard["HashKeyRange"]["EndingHashKey"]))


def _await_active(kin, name: str) -> str:
    """Poll until the stream is ACTIVE *and* ListShards agrees; returns the StreamARN.

    DescribeStreamSummary can report ACTIVE while ListShards still raises ResourceInUseException.
    """
    deadline = time.monotonic() + 300
    status = ""
    while time.monotonic() < deadline:
        summary = kin.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        status = summary["StreamStatus"]
        if status == "ACTIVE":
            try:
                kin.list_shards(StreamName=name)
                return summary["StreamARN"]
            except kin.exceptions.ResourceInUseException:
                pass
        time.sleep(2)
    raise AssertionError(
        f"stream {name!r} never became ACTIVE and listable; last status {status!r}"
    )


def _delete_stream(kin, name: str) -> None:
    """Teardown: delete the stream; ResourceNotFoundException means the body already deleted it."""
    try:
        kin.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except kin.exceptions.ResourceNotFoundException:
        return


def _contents(kin, name: str, shard_ids: list[str]) -> collections.Counter:
    """The multiset of every record on the named shards, read from TRIM_HORIZON."""
    total: collections.Counter = collections.Counter()
    for shard_id in shard_ids:
        iterator = kin.get_shard_iterator(
            StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
        for _ in range(200):
            resp = kin.get_records(ShardIterator=iterator, Limit=1000)
            for record in resp["Records"]:
                total[(shard_id, record["PartitionKey"], record["Data"].decode())] += 1
            iterator = resp.get("NextShardIterator")
            if iterator is None:
                break
            if not resp["Records"] and resp.get("MillisBehindLatest", 1) == 0:
                break
            time.sleep(0.25)
    return total


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """SplitShard at the parent's StartingHashKey or one step outside its range is rejected with
    InvalidArgumentException and leaves shard map, open state and contents unchanged; the
    midpoint is accepted.
    """
    kin = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-d5-")

    kin.create_stream(StreamName=name, ShardCount=2,
                      StreamModeDetails={"StreamMode": "PROVISIONED"},
                      Tags={"sim2real": "ga-depth-kinesis"})
    ctx.on_cleanup(lambda: _delete_stream(kin, name))
    stream_arn = _await_active(kin, name)

    shards = sorted(_list_shards(kin, name), key=lambda s: _range(s)[0])
    assert len(shards) == 2, f"a 2-shard stream reported {len(shards)} shards"
    parent = shards[1]["ShardId"]
    p_lo, p_hi = _range(shards[1])
    shard_ids = [s["ShardId"] for s in shards]

    # ---- full setup: real records, so "unchanged" is a claim about contents, not just shape #
    keys = [f"k-{name}-{i}" for i in range(N_KEYS)]
    for ordinal in range(PER_KEY):
        resp = kin.put_records(StreamName=name, Records=[
            {"PartitionKey": key, "Data": f"{i}:{ordinal}".encode()}
            for i, key in enumerate(keys)])
        assert resp["FailedRecordCount"] == 0, f"put_records failed: {resp!r}"
        for i, entry in enumerate(resp["Records"]):
            lo, hi = _range(next(s for s in shards if s["ShardId"] == entry["ShardId"]))
            assert lo <= _md5_int(keys[i]) <= hi, (
                f"{keys[i]!r} (MD5 {_md5_int(keys[i])}) was routed to {entry['ShardId']!r} "
                f"whose range is {(lo, hi)!r}"
            )
    # bounded retry, not an unconditional sleep: a just-written record is not
    # guaranteed to be readable from TRIM_HORIZON on the very next GetRecords.
    deadline = time.monotonic() + 30
    before: collections.Counter = collections.Counter()
    while time.monotonic() < deadline:
        before = _contents(kin, name, shard_ids)
        if sum(before.values()) == N_KEYS * PER_KEY:
            break
        time.sleep(2)
    assert sum(before.values()) == N_KEYS * PER_KEY, (
        f"the stream held {sum(before.values())} records 30s after put_records, "
        f"expected {N_KEYS * PER_KEY}: {before!r}"
    )

    # ---- a split point outside the parent's range; StartingHashKey itself = empty low child -- #
    for label, candidate in (
        ("one below the parent's StartingHashKey", p_lo - 1),
        ("the parent's StartingHashKey itself (an empty low child)", p_lo),
        ("one above the parent's EndingHashKey", p_hi + 1),
    ):
        err = _client_error(kin.split_shard, StreamName=name, ShardToSplit=parent,
                            NewStartingHashKey=str(candidate))
        assert err["Code"] == "InvalidArgumentException", (
            f"SplitShard at {label} ({candidate}) on a parent covering {(p_lo, p_hi)!r} was "
            f"rejected with {err!r}, expected 'InvalidArgumentException'"
        )
        expected = (
            f"NewStartingHashKey {candidate} used in SplitShard() on shard {parent} in stream "
            f"{name} under account {stream_arn.split(':')[4]} is not both greater than one plus "
            f"the shard's StartingHashKey {p_lo} and less than the shard's EndingHashKey {p_hi}."
        )
        assert err["Message"] == expected, (
            f"SplitShard at {label} answered {err['Message']!r}, expected {expected!r}"
        )

    # ---- the effect must be absent: shard map, open state and contents all unchanged ------ #
    still = _list_shards(kin, name)
    assert len(still) == 2, (
        f"a rejected SplitShard changed the shard map to {[s['ShardId'] for s in still]!r}"
    )
    assert [_range(s) for s in sorted(still, key=lambda s: _range(s)[0])] == [_range(s) for s in shards], (
        f"a rejected SplitShard moved a hash range: {[_range(s) for s in still]!r}"
    )
    open_parent = next(s for s in still if s["ShardId"] == parent)
    assert open_parent["SequenceNumberRange"].get("EndingSequenceNumber") is None, (
        f"a rejected SplitShard closed the parent: {open_parent['SequenceNumberRange']!r}"
    )
    assert _contents(kin, name, shard_ids) == before, (
        "a rejected SplitShard changed the shards' contents"
    )

    # ---- positive control in the same file: the midpoint of the same parent is accepted --- #
    mid = (p_lo + p_hi) // 2
    kin.split_shard(StreamName=name, ShardToSplit=parent, NewStartingHashKey=str(mid))
    children: list[dict] = []
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        after = _list_shards(kin, name)
        children = sorted((s for s in after if s.get("ParentShardId") == parent),
                          key=lambda s: _range(s)[0])
        closed = next(s for s in after if s["ShardId"] == parent)
        if len(children) == 2 and closed["SequenceNumberRange"].get("EndingSequenceNumber"):
            break
        time.sleep(3)
    assert len(children) == 2, (
        f"the control SplitShard at the midpoint {mid} produced {len(children)} children"
    )
    assert _range(children[0]) == (p_lo, mid - 1), (
        f"the low child covers {_range(children[0])!r}, expected {(p_lo, mid - 1)!r}"
    )
    assert _range(children[1]) == (mid, p_hi), (
        f"the high child covers {_range(children[1])!r}, expected {(mid, p_hi)!r}"
    )
    assert next(s for s in _list_shards(kin, name)
                if s["ShardId"] == parent)["SequenceNumberRange"].get("EndingSequenceNumber"), (
        "the control SplitShard succeeded but left the parent open"
    )

    # ---- verified teardown --------------------------------------------------------------- #
    kin.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    gone = False
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            kin.describe_stream_summary(StreamName=name)
        except kin.exceptions.ResourceNotFoundException:
            gone = True
            break
        time.sleep(3)
    assert gone, f"stream {name!r} was still describable 120 s after delete_stream"

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
