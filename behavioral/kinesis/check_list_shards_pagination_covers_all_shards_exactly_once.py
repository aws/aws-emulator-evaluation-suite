"""list-shards-pagination-covers-all-shards-exactly-once."""
from __future__ import annotations

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
            c.create_stream(StreamName=name, Tags={"sim2real": "ga-depth-kinesis"}, **params)
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


CHECK = "list-shards-pagination-covers-all-shards-exactly-once"
GROUP = 'listing'
SERVICES = ['kinesis']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListShards paging visits every shard exactly once, and a NextToken is cross-checked against
    any stream identifier sent with it: its own stream is accepted, another is InvalidArgument.
    """
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=3)
    all_shards = _shard_ids(c, name)
    assert len(all_shards) == 3, f"expected a 3-shard stream, ListShards gave {all_shards}"

    # Page one shard at a time. Only the first call carries StreamName.
    pages = []
    resp = c.list_shards(StreamName=name, MaxResults=1)
    while True:
        pages.append([s["ShardId"] for s in resp["Shards"]])
        token = resp.get("NextToken")
        if not token:
            break
        assert len(pages) <= 10, (
            f"ListShards paging did not terminate after {len(pages)} pages over a 3-shard "
            f"stream; pages so far: {pages}"
        )
        resp = c.list_shards(NextToken=token, MaxResults=1)

    assert all(len(p) <= 1 for p in pages), (
        f"MaxResults=1 must cap each page at one shard, got page sizes "
        f"{[len(p) for p in pages]}: {pages}"
    )
    seen = [sid for p in pages for sid in p]
    assert len(seen) == len(set(seen)), (
        f"ListShards paging returned a shard more than once: {seen}"
    )
    assert sorted(seen) == sorted(all_shards), (
        f"ListShards paging visited {sorted(seen)} across {len(pages)} pages; the stream's "
        f"shards are {sorted(all_shards)} — paging must cover every shard exactly once"
    )
    # A trailing page carrying zero shards is legal (NextToken means "there may be more"),
    # so the strict count is over pages that actually carried a shard.
    populated = [p for p in pages if p]
    assert len(populated) == 3, (
        f"a 3-shard stream paged at MaxResults=1 must take 3 populated pages, took "
        f"{len(populated)} of {len(pages)}: {pages}"
    )

    # The token carries its stream identity: a matching StreamName/StreamARN is accepted, a
    # different (even nonexistent) StreamName is InvalidArgumentException, not ResourceNotFound,
    # because the token-consistency test runs before the stream lookup.
    first = c.list_shards(StreamName=name, MaxResults=1)
    token = first.get("NextToken")
    assert token, (
        f"precondition failed: ListShards(MaxResults=1) over 3 shards returned no NextToken: "
        f"{first.get('Shards')}"
    )
    # Consistent pair: accepted, and it must resolve to exactly the same page as the token alone.
    with_name = [s["ShardId"] for s in c.list_shards(StreamName=name, NextToken=token)["Shards"]]
    token_only = [s["ShardId"] for s in c.list_shards(NextToken=token)["Shards"]]
    assert with_name == token_only, (
        f"a NextToken sent together with the StreamName it was minted for must resolve to the "
        f"identical page as the token alone, got {with_name} vs {token_only}"
    )
    assert with_name == all_shards[1:], (
        f"the second page of a MaxResults=1 walk must be the remaining shards {all_shards[1:]}, "
        f"got {with_name}"
    )
    stream_arn = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    with_arn = [s["ShardId"] for s in c.list_shards(StreamARN=stream_arn, NextToken=token)["Shards"]]
    assert with_arn == token_only, (
        f"the StreamARN of the token's own stream must be accepted alongside the token and "
        f"resolve to the same page, got {with_arn} vs {token_only}"
    )

    # Break exactly one thing: keep the token, change the StreamName to a different stream.
    mismatched = ctx.unique_name("sim2real-behav-kds-absent-")
    try:
        c.list_shards(StreamName=mismatched, NextToken=token)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message", "")
        assert code == "InvalidArgumentException", (
            f"ListShards(NextToken + a StreamName the token was not minted for) failed with "
            f"{code}; real AWS answers InvalidArgumentException — and specifically not "
            f"ResourceNotFoundException, even though {mismatched!r} does not exist, because the "
            f"token-consistency test precedes the stream lookup"
        )
        expected_message = "NextToken does not match the provided StreamName."
        assert message == expected_message, (
            f"expected message {expected_message!r}, got {message!r}"
        )
    else:
        raise AssertionError(
            f"ListShards ACCEPTED NextToken for {name!r} together with StreamName "
            f"{mismatched!r}; real AWS cross-checks the two and refuses with "
            f"InvalidArgumentException. Accepting ignored input here is the over-permissive "
            f"failure mode: paging code that carries the wrong stream name works against the "
            f"emulator and breaks against AWS"
        )

    # Effect absent: the refusal did not consume or invalidate the token, which is still
    # usable on its own.
    resumed = c.list_shards(NextToken=token)
    resumed_ids = [s["ShardId"] for s in resumed["Shards"]]
    assert resumed_ids, f"the NextToken returned no shards after the refused call: {resumed}"
    assert set(resumed_ids) <= set(all_shards), (
        f"resuming from the token returned shards outside the stream: {resumed_ids} vs {all_shards}"
    )

    # Control: the unpaged call still returns the full set.
    assert sorted(_shard_ids(c, name)) == sorted(all_shards), (
        f"plain ListShards stopped returning all 3 shards after the refusal: "
        f"{_shard_ids(c, name)}"
    )

    # ExclusiveStartShardId is the other, non-token cursor: it is exclusive of the named shard.
    after_first = c.list_shards(StreamName=name, ExclusiveStartShardId=all_shards[0])
    after_ids = [s["ShardId"] for s in after_first["Shards"]]
    assert after_ids == all_shards[1:], (
        f"ExclusiveStartShardId={all_shards[0]} returned {after_ids}; it must be exclusive of "
        f"the named shard and yield exactly {all_shards[1:]}"
    )
    after_last = c.list_shards(StreamName=name, ExclusiveStartShardId=all_shards[-1])
    assert after_last["Shards"] == [], (
        f"ExclusiveStartShardId={all_shards[-1]} (the last shard) must return no shards, got "
        f"{[s['ShardId'] for s in after_last['Shards']]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
