"""list-shards-shard-filter-resolves-the-resharding-lineage."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-shards-shard-filter-resolves-the-resharding-lineage"
GROUP = "resharding"
SERVICES = ["kinesis"]

#: 2**128 - 1 is the top of a Kinesis stream's MD5 hash space; a one-shard stream owns all of it.
_HASH_SPACE_TOP = 2**128 - 1
_PRE_SPLIT_PAYLOADS = tuple(f"pre-split-{i}".encode() for i in range(3))


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListShards ShardFilter on a split stream: AT_LATEST gives the open children, AT_TRIM_HORIZON
    the parent, FROM_TRIM_HORIZON all, AFTER_SHARD_ID the tail, AT_TIMESTAMP the shards open then.
    An extraneous ShardId is ignored; AFTER_SHARD_ID without one is an InvalidArgumentException."""
    kinesis = ctx.client("kinesis")
    stream = _create_active_stream(ctx)
    parent = _single_shard(ctx, stream["name"])
    parent_id = parent["ShardId"]

    assert parent["HashKeyRange"]["StartingHashKey"] == "0", (
        f"a fresh one-shard stream's shard starts at hash key "
        f"{parent['HashKeyRange']['StartingHashKey']!r}; expected '0'"
    )
    assert parent["HashKeyRange"]["EndingHashKey"] == str(_HASH_SPACE_TOP), (
        f"a fresh one-shard stream's shard ends at hash key "
        f"{parent['HashKeyRange']['EndingHashKey']!r}; expected {str(_HASH_SPACE_TOP)!r}"
    )
    assert "EndingSequenceNumber" not in parent["SequenceNumberRange"], (
        f"shard {parent_id} reports an EndingSequenceNumber before any resharding; an open shard "
        "must not have one"
    )

    for payload in _PRE_SPLIT_PAYLOADS:
        kinesis.put_record(
            StreamName=stream["name"], Data=payload, PartitionKey=payload.decode()
        )

    before_split = datetime.now(timezone.utc)

    midpoint = (_HASH_SPACE_TOP + 1) // 2
    kinesis.split_shard(
        StreamName=stream["name"], ShardToSplit=parent_id, NewStartingHashKey=str(midpoint)
    )
    _wait_active(ctx, stream["name"], timeout_s=300.0)
    all_shards = _poll_until(
        lambda: _list_shards(kinesis, stream["name"]),
        lambda s: len(s) == 3,
        timeout_s=120.0,
        interval_s=3.0,
        description=f"SplitShard on {parent_id} to yield exactly 3 shards (parent + 2 children)",
    )

    by_id = {s["ShardId"]: s for s in all_shards}
    all_ids = set(by_id)
    child_ids = all_ids - {parent_id}
    assert len(child_ids) == 2, (
        f"expected exactly 2 child shards after splitting {parent_id}, got {sorted(child_ids)} "
        f"out of {sorted(all_ids)}"
    )
    lower, upper = sorted(
        (by_id[c] for c in child_ids), key=lambda s: int(s["HashKeyRange"]["StartingHashKey"])
    )

    # ---- Structural closure: the children partition the parent's range exactly ----
    for child in (lower, upper):
        assert child.get("ParentShardId") == parent_id, (
            f"child {child['ShardId']} reports ParentShardId "
            f"{child.get('ParentShardId')!r}; expected {parent_id!r}"
        )
        assert "AdjacentParentShardId" not in child, (
            f"child {child['ShardId']} of a SPLIT reports AdjacentParentShardId "
            f"{child.get('AdjacentParentShardId')!r}; only merge children have one"
        )
    assert lower["HashKeyRange"]["StartingHashKey"] == "0", (
        f"lower child {lower['ShardId']} starts at "
        f"{lower['HashKeyRange']['StartingHashKey']!r}; expected the parent's start '0'"
    )
    assert upper["HashKeyRange"]["StartingHashKey"] == str(midpoint), (
        f"upper child {upper['ShardId']} starts at "
        f"{upper['HashKeyRange']['StartingHashKey']!r}; expected the requested "
        f"NewStartingHashKey {str(midpoint)!r}"
    )
    assert upper["HashKeyRange"]["EndingHashKey"] == str(_HASH_SPACE_TOP), (
        f"upper child {upper['ShardId']} ends at "
        f"{upper['HashKeyRange']['EndingHashKey']!r}; expected the parent's end "
        f"{str(_HASH_SPACE_TOP)!r}"
    )
    assert int(lower["HashKeyRange"]["EndingHashKey"]) + 1 == midpoint, (
        f"lower child {lower['ShardId']} ends at "
        f"{lower['HashKeyRange']['EndingHashKey']!r}; the two children must tile the parent's range "
        f"with no gap and no overlap, so it must end at {midpoint - 1}"
    )
    assert "EndingSequenceNumber" in by_id[parent_id]["SequenceNumberRange"], (
        f"parent {parent_id} has no EndingSequenceNumber after being split; a split parent is closed"
    )

    # ---- The filter matrix. Every expected set is derived from the lineage above ----
    unfiltered = all_ids
    from_trim = _filtered_ids(kinesis, stream["name"], {"Type": "FROM_TRIM_HORIZON"})
    assert from_trim == unfiltered, (
        "ShardFilter Type=FROM_TRIM_HORIZON is documented as the DEFAULT, so it must return the "
        f"same set as an unfiltered ListShards ({sorted(unfiltered)}); it returned "
        f"{sorted(from_trim)}"
    )

    # ShardFilter answers lag plain ListShards after SplitShard (AT_LATEST can still include the
    # closed parent), so each filtered read is a bounded poll for convergence.
    _FILTER_CONVERGE_TIMEOUT_S = 60.0

    at_latest = _poll_until(
        lambda: _filtered_ids(kinesis, stream["name"], {"Type": "AT_LATEST"}),
        lambda ids: ids == child_ids,
        timeout_s=_FILTER_CONVERGE_TIMEOUT_S,
        interval_s=3.0,
        description=(
            f"ShardFilter Type=AT_LATEST to converge on the open children {sorted(child_ids)} "
            f"(closed parent {parent_id} excluded) after SplitShard"
        ),
    )
    assert at_latest == child_ids, (
        f"ShardFilter Type=AT_LATEST converged to {sorted(at_latest)}; expected only the "
        f"currently OPEN shards {sorted(child_ids)} — the split parent {parent_id} is closed and "
        "must be excluded"
    )
    # AT_TIMESTAMP resolves a fixed instant, so a timestamp taken before the graph settled stays
    # wrong; one taken after AT_LATEST shows the children open is on the right side of the split.
    after_split = datetime.now(timezone.utc)

    at_trim = _poll_until(
        lambda: _filtered_ids(kinesis, stream["name"], {"Type": "AT_TRIM_HORIZON"}),
        lambda ids: ids == {parent_id},
        timeout_s=_FILTER_CONVERGE_TIMEOUT_S,
        interval_s=3.0,
        description=(
            f"ShardFilter Type=AT_TRIM_HORIZON to converge on exactly the parent {parent_id!r}"
        ),
    )
    assert at_trim == {parent_id}, (
        f"ShardFilter Type=AT_TRIM_HORIZON converged to {sorted(at_trim)}; the stream is seconds "
        f"old so the only shard open at TRIM_HORIZON was the parent {parent_id}"
    )

    expected_after = {i for i in all_ids if i > parent_id}
    after_parent = _poll_until(
        lambda: _filtered_ids(
            kinesis, stream["name"], {"Type": "AFTER_SHARD_ID", "ShardId": parent_id}
        ),
        lambda ids: ids == expected_after,
        timeout_s=_FILTER_CONVERGE_TIMEOUT_S,
        interval_s=3.0,
        description=(
            f"ShardFilter Type=AFTER_SHARD_ID ShardId={parent_id} to converge on "
            f"{sorted(expected_after)}"
        ),
    )
    assert after_parent == expected_after, (
        f"ShardFilter Type=AFTER_SHARD_ID ShardId={parent_id} converged to {sorted(after_parent)}; "
        f"expected every shard whose id sorts after it, {sorted(expected_after)}"
    )

    at_before = _poll_until(
        lambda: _filtered_ids(
            kinesis, stream["name"], {"Type": "AT_TIMESTAMP", "Timestamp": before_split}
        ),
        lambda ids: ids == {parent_id},
        timeout_s=_FILTER_CONVERGE_TIMEOUT_S,
        interval_s=3.0,
        description=(
            f"ShardFilter Type=AT_TIMESTAMP at {before_split.isoformat()} (captured BEFORE the "
            f"split) to converge on exactly the parent {parent_id!r}"
        ),
    )
    assert at_before == {parent_id}, (
        f"ShardFilter Type=AT_TIMESTAMP at {before_split.isoformat()} (captured from the live "
        f"clock BEFORE the split) converged to {sorted(at_before)}; only the parent {parent_id} "
        "existed then"
    )
    at_after = _poll_until(
        lambda: _filtered_ids(
            kinesis, stream["name"], {"Type": "AT_TIMESTAMP", "Timestamp": after_split}
        ),
        lambda ids: ids == child_ids,
        timeout_s=_FILTER_CONVERGE_TIMEOUT_S,
        interval_s=3.0,
        description=(
            f"ShardFilter Type=AT_TIMESTAMP at {after_split.isoformat()} (captured AFTER the "
            f"split) to converge on the open children {sorted(child_ids)}"
        ),
    )
    assert at_after == child_ids, (
        f"ShardFilter Type=AT_TIMESTAMP at {after_split.isoformat()} (captured AFTER the split "
        f"completed) converged to {sorted(at_after)}; expected the open children "
        f"{sorted(child_ids)}"
    )

    # ---- A ShardId outside AFTER_SHARD_ID is not refused: real AWS accepts and ignores it ----
    # ShardId is only consulted for AFTER_SHARD_ID; with AT_LATEST it is ignored.
    at_latest_extra_shard_id = _filtered_ids(
        kinesis, stream["name"], {"Type": "AT_LATEST", "ShardId": parent_id}
    )
    assert at_latest_extra_shard_id == child_ids, (
        f"ShardFilter Type=AT_LATEST with an extraneous ShardId={parent_id} returned "
        f"{sorted(at_latest_extra_shard_id)}; AWS accepts (and must ignore) a ShardId outside "
        f"AFTER_SHARD_ID, so this must equal the same {sorted(child_ids)} that AT_LATEST returns "
        "with no ShardId at all"
    )

    # ---- AFTER_SHARD_ID with no ShardId IS refused: that field is genuinely required for it ----
    err = _client_error(
        lambda: kinesis.list_shards(
            StreamName=stream["name"], ShardFilter={"Type": "AFTER_SHARD_ID"}
        )
    )
    assert err.get("Code") == "InvalidArgumentException", (
        "ShardFilter Type=AFTER_SHARD_ID with no ShardId must be refused; expected "
        f"InvalidArgumentException, got {err.get('Code')!r}: {err.get('Message')!r}"
    )
    assert err.get("Message") == "ShardId must be provided when the ShardFilter Type is AFTER_SHARD_ID.", (
        f'expected the exact InvalidArgumentException message AWS returns, got {err.get("Message")!r}'
    )

    # ---- Effect-absent, and the terminal independent read: neither call changed anything ----
    assert _filtered_ids(kinesis, stream["name"], {"Type": "AT_LATEST"}) == child_ids, (
        f"after an accepted ShardFilter with an extraneous ShardId and a refused ShardFilter, "
        f"AT_LATEST no longer returns {sorted(child_ids)}; neither a read nor a rejected read may "
        "mutate the shard lineage"
    )
    assert _list_shard_ids(kinesis, stream["name"]) == unfiltered, (
        f"after an accepted ShardFilter with an extraneous ShardId and a refused ShardFilter, the "
        f"unfiltered shard set changed from {sorted(unfiltered)}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}; last observation: {last!r}"
    )


def _client_error(fn) -> dict:
    """Return the botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _create_active_stream(ctx, *, shard_count: int = 1) -> dict[str, str]:
    """Create-or-adopt a provisioned stream, tagged, and wait until it is ACTIVE."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kds-")
    try:
        kinesis.create_stream(
            StreamName=name,
            ShardCount=shard_count,
            StreamModeDetails={"StreamMode": "PROVISIONED"},
            Tags={"sim2real": "behavioral", "sim2real-check": CHECK},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceInUseException":
            raise
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    summary = _wait_active(ctx, name)
    return {"name": name, "arn": summary["StreamARN"]}


def _wait_active(ctx, stream_name: str, *, timeout_s: float = 240.0) -> dict:
    kinesis = ctx.client("kinesis")
    return _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=stream_name)[
            "StreamDescriptionSummary"
        ],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"stream {stream_name} to reach ACTIVE",
    )


def _list_shards(kinesis, stream_name: str, shard_filter: dict | None = None) -> list[dict]:
    """Every shard across every page. ListShards can briefly 404/409 right after a state change."""
    kwargs: dict = {"StreamName": stream_name, "MaxResults": 100}
    if shard_filter is not None:
        kwargs["ShardFilter"] = shard_filter
    shards: list[dict] = []
    token = None
    while True:
        if token:
            page_kwargs: dict = {"NextToken": token, "MaxResults": 100}
        else:
            page_kwargs = dict(kwargs)
        try:
            page = kinesis.list_shards(**page_kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "ResourceInUseException",
                "ResourceNotFoundException",
            ):
                return []
            raise
        shards.extend(page["Shards"])
        token = page.get("NextToken")
        if not token:
            return shards


def _list_shard_ids(kinesis, stream_name: str) -> set[str]:
    return {s["ShardId"] for s in _list_shards(kinesis, stream_name)}


def _filtered_ids(kinesis, stream_name: str, shard_filter: dict) -> set[str]:
    return {s["ShardId"] for s in _list_shards(kinesis, stream_name, shard_filter)}


def _single_shard(ctx, stream_name: str) -> dict:
    """Poll until exactly one shard is addressable, and return it."""
    kinesis = ctx.client("kinesis")
    shards = _poll_until(
        lambda: _list_shards(kinesis, stream_name),
        lambda s: len(s) == 1,
        timeout_s=90.0,
        interval_s=3.0,
        description=f"exactly one shard to be addressable on {stream_name}",
    )
    return shards[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
