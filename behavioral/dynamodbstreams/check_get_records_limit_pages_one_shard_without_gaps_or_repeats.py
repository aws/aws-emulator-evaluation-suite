"""get-records-limit-pages-one-shard-without-gaps-or-repeats."""
from __future__ import annotations

import math
import time

from behavioral_harness import tags

CHECK = "get-records-limit-pages-one-shard-without-gaps-or-repeats"
GROUP = "pagination"
SERVICES = ["dynamodbstreams"]

_WRITES = 12
_LIMIT = 3


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRecords(Limit=3) over a shard holding 12 records caps every page at 3 and, chained to
    exhaustion, reproduces the unpaginated read exactly: same records, order and sequence numbers.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_streams_GetRecords.html
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table, stream_arn = _create_stream_table(
        ctx, ddb, "NEW_IMAGE", "sim2real-behav-dbslimit-")
    _desc, shard_ids, horizon = _wait_stream_usable(streams, stream_arn)

    key = {"pk": {"S": "limit-item"}}
    for n in range(1, _WRITES + 1):
        ddb.put_item(TableName=table, Item={**key, "v": {"N": str(n)}})

    # --- positive control: the unpaginated read, on the same shard, in the same run ---
    tagged = _drain(streams, shard_ids, horizon, want=_WRITES)
    assert len(tagged) == _WRITES, (
        f"the unpaginated control must see all {_WRITES} writes before the paged read is "
        f"compared against it; drained {len(tagged)}"
    )
    landed = {shard for shard, _rec in tagged}
    assert len(landed) == 1, (
        f"all writes to one partition key must land on ONE shard, so the paging surface under "
        f"test is a single iterator chain; they landed on {sorted(landed)!r}"
    )
    shard = landed.pop()
    expected_values = [str(n) for n in range(1, _WRITES + 1)]
    baseline_values = [rec["dynamodb"]["NewImage"]["v"]["N"] for _s, rec in tagged]
    baseline_seqs = [rec["dynamodb"]["SequenceNumber"] for _s, rec in tagged]
    assert baseline_values == expected_values, (
        f"the unpaginated control must replay the writes in order; expected {expected_values!r}, "
        f"got {baseline_values!r}"
    )

    # --- the subject: the same shard, read again from TRIM_HORIZON, capped at _LIMIT per page ---
    cursor = streams.get_shard_iterator(
        StreamArn=stream_arn, ShardId=shard, ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    paged, page_sizes = _drain_paged(
        streams, cursor, limit=_LIMIT, want=_WRITES, shard=shard)

    oversized = [(i, n) for i, n in enumerate(page_sizes) if n > _LIMIT]
    assert not oversized, (
        f"GetRecords(Limit={_LIMIT}) must never return more than {_LIMIT} records in one page; "
        f"pages {[i for i, _n in oversized]} returned {[n for _i, n in oversized]} records "
        f"respectively (all page sizes in order: {page_sizes!r}). A target that ignores Limit "
        f"hands the consumer a batch it never asked for"
    )

    nonempty = [n for n in page_sizes if n]
    least_pages = math.ceil(_WRITES / _LIMIT)
    assert len(nonempty) >= least_pages, (
        f"reading {_WRITES} records {_LIMIT} at a time needs at least "
        f"ceil({_WRITES}/{_LIMIT})={least_pages} non-empty pages; the read used "
        f"{len(nonempty)} (sizes {nonempty!r})"
    )
    assert sum(nonempty) == _WRITES, (
        f"the paged pages must account for exactly {_WRITES} records with none dropped and none "
        f"duplicated; they sum to {sum(nonempty)} (sizes {nonempty!r})"
    )
    assert max(nonempty) == _LIMIT, (
        f"with all {_WRITES} records already durable in shard {shard}, at least one page must be "
        f"FULL at the requested Limit of {_LIMIT}; the largest page held {max(nonempty)} "
        f"(sizes {nonempty!r}). A target that serves one record per page regardless of Limit "
        f"lands here"
    )

    paged_values = [rec["dynamodb"]["NewImage"]["v"]["N"] for rec in paged]
    paged_seqs = [rec["dynamodb"]["SequenceNumber"] for rec in paged]
    assert paged_values == baseline_values, (
        f"paging must not change WHAT is read or the order it is read in: the unpaginated "
        f"control yielded {baseline_values!r}, the Limit={_LIMIT} read yielded {paged_values!r} "
        f"over pages {page_sizes!r}"
    )
    assert paged_seqs == baseline_seqs, (
        f"paging must return the SAME sequence numbers, in the same order, as the unpaginated "
        f"read: expected {baseline_seqs!r}, got {paged_seqs!r}"
    )
    assert len(set(paged_seqs)) == _WRITES, (
        f"no record may be served twice across page boundaries: {_WRITES} records yielded "
        f"{len(set(paged_seqs))} distinct sequence numbers ({paged_seqs!r})"
    )
    ascending = [int(s) for s in paged_seqs]
    assert all(b > a for a, b in zip(ascending, ascending[1:])), (
        f"sequence numbers must increase strictly across the whole paged read, including at the "
        f"page boundaries where a target is most likely to reorder or rewind; got {paged_seqs!r} "
        f"over pages {page_sizes!r}"
    )


def _drain_paged(streams, cursor: str, *, limit: int, want: int, shard: str,
                 timeout_s: float = 150.0, interval_s: float = 2.0):
    """Chain GetRecords(Limit=limit) until ``want`` records arrive; return (records, page_sizes).

    Empty pages are legal mid-shard, so they are chained through. Raises on a short chain.
    """
    records: list = []
    page_sizes: list = []
    deadline = time.monotonic() + timeout_s
    while len(records) < want:
        resp = streams.get_records(ShardIterator=cursor, Limit=limit)
        got = resp.get("Records", [])
        page_sizes.append(len(got))
        records.extend(got)
        nxt = resp.get("NextShardIterator")
        if len(records) >= want:
            break
        if not nxt:
            raise AssertionError(
                f"the Limit={limit} iterator chain on OPEN shard {shard} ended after "
                f"{len(page_sizes)} pages (sizes {page_sizes!r}) holding only {len(records)} of "
                f"{want} records; an open shard must keep handing back a NextShardIterator"
            )
        cursor = nxt
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the Limit={limit} read of shard {shard} collected {len(records)} of {want} "
                f"records over {len(page_sizes)} pages in {timeout_s}s (sizes {page_sizes!r})"
            )
        if not got:
            time.sleep(interval_s)
    return records, page_sizes


def _create_stream_table(ctx, ddb, view_type: str, prefix: str) -> tuple[str, str]:
    name = ctx.unique_name(prefix)
    created = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": view_type},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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

    GetShardIterator can answer ResourceNotFoundException briefly after the stream is ENABLED.
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


def _drain(streams, shard_ids: list, iterators: list, *, want: int, timeout_s: float = 150.0):
    """Follow every shard's NextShardIterator chain, with no Limit, until ``want`` records arrive.

    A fresh iterator's first GetRecords can legitimately return zero records, so this polls.
    """
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
