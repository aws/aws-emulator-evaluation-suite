"""parallel-scan-totalsegments-4-segments-nest-exactly-inside-totalsegments-2-halves."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "parallel-scan-totalsegments-4-segments-nest-exactly-inside-totalsegments-2-halves"
GROUP = "scan"
SERVICES = ["dynamodb"]

_ITEMS = 256
_WRITTEN = [f"nest-{i:04d}" for i in range(_ITEMS)]


def _batch_write(ddb, table: str, keys: list[str]) -> None:
    """PutRequest every key in 25-item BatchWriteItem calls; raises on any unprocessed item."""
    for offset in range(0, len(keys), 25):
        batch = keys[offset:offset + 25]
        resp = ddb.batch_write_item(RequestItems={
            table: [{"PutRequest": {"Item": {"pk": {"S": k}}}} for k in batch]
        })
        assert resp["UnprocessedItems"] == {}, (
            f"BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed while seeding"
        )


def _scan_segment(ddb, table: str, total_segments: int, segment: int) -> set[str]:
    """Every pk one segment of a (total_segments, segment) parallel Scan returns, fully paged."""
    keys: set[str] = set()
    start: dict = {}
    while True:
        page = ddb.scan(TableName=table, TotalSegments=total_segments, Segment=segment,
                        ConsistentRead=True, **start)
        keys.update(item["pk"]["S"] for item in page["Items"])
        if "LastEvaluatedKey" not in page:
            return keys
        start = {"ExclusiveStartKey": page["LastEvaluatedKey"]}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Doubling TotalSegments from 2 to 4 only ever splits a segment: each TotalSegments=4
    segment's items are a subset of exactly one TotalSegments=2 segment's items, and a
    TotalSegments=2 segment's items are exactly the union of its two TotalSegments=4 children.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html#Scan.ParallelScan
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-nest-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    _batch_write(ddb, table, _WRITTEN)

    halves = {h: _scan_segment(ddb, table, 2, h) for h in (0, 1)}
    quarters = {q: _scan_segment(ddb, table, 4, q) for q in (0, 1, 2, 3)}

    all_from_halves = halves[0] | halves[1]
    all_from_quarters = quarters[0] | quarters[1] | quarters[2] | quarters[3]
    assert all_from_halves == set(_WRITTEN), (
        f"TotalSegments=2 must cover every written key; symmetric difference "
        f"{sorted(all_from_halves ^ set(_WRITTEN))[:20]!r}"
    )
    assert all_from_quarters == set(_WRITTEN), (
        f"TotalSegments=4 must cover every written key; symmetric difference "
        f"{sorted(all_from_quarters ^ set(_WRITTEN))[:20]!r}"
    )

    for q in (0, 1, 2, 3):
        assert quarters[q], f"TotalSegments=4 segment {q} came back empty with {_ITEMS} items written"

    # --- the nesting claim: segment q's parent is whichever half contains ALL of q's keys ---
    parent_of = {}
    for q, keys in quarters.items():
        containing = [h for h in (0, 1) if keys <= halves[h]]
        assert len(containing) == 1, (
            f"TotalSegments=4 segment {q} ({len(keys)} keys) must nest inside exactly one "
            f"TotalSegments=2 half; it fits inside {containing!r} "
            f"(half sizes {[len(halves[h]) for h in (0, 1)]!r})"
        )
        parent_of[q] = containing[0]

    for h in (0, 1):
        children = [q for q, p in parent_of.items() if p == h]
        assert len(children) == 2, (
            f"TotalSegments=2 half {h} must have exactly 2 TotalSegments=4 children, got "
            f"{children!r} (parent map {parent_of!r})"
        )
        union = quarters[children[0]] | quarters[children[1]]
        assert union == halves[h], (
            f"half {h}'s two children {children!r} must union to exactly half {h}'s "
            f"{len(halves[h])} keys; symmetric difference {sorted(union ^ halves[h])[:20]!r}"
        )
        assert quarters[children[0]].isdisjoint(quarters[children[1]]), (
            f"half {h}'s two children {children!r} must be disjoint; overlap "
            f"{sorted(quarters[children[0]] & quarters[children[1]])[:10]!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
