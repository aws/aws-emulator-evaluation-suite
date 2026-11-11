"""parallel-scan-segment-co-locates-every-sort-key-under-one-partition-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "parallel-scan-segment-co-locates-every-sort-key-under-one-partition-key"
GROUP = "scan"
SERVICES = ["dynamodb"]

_TOTAL_SEGMENTS = 4
_PKS = tuple(f"pk{i:03d}" for i in range(16))
_SKS = ("sk-a", "sk-b", "sk-c", "sk-d")


def _batch_write(ddb, table: str, items: list) -> None:
    """PutRequest every item in 25-item BatchWriteItem calls; raises on any unprocessed item."""
    for offset in range(0, len(items), 25):
        resp = ddb.batch_write_item(RequestItems={table: items[offset:offset + 25]})
        assert resp["UnprocessedItems"] == {}, (
            f"BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed while seeding"
        )


def _scan_segment(ddb, table: str, segment: int) -> list:
    """Every item one segment of a TotalSegments=4 parallel Scan returns, fully paged."""
    items: list = []
    start: dict = {}
    while True:
        page = ddb.scan(TableName=table, TotalSegments=_TOTAL_SEGMENTS, Segment=segment,
                        ConsistentRead=True, **start)
        items += page["Items"]
        if "LastEvaluatedKey" not in page:
            return items
        start = {"ExclusiveStartKey": page["LastEvaluatedKey"]}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A parallel Scan assigns every item of one partition key to the same segment: a
    partition key's sort keys never split across two of the TotalSegments=4 segments.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html#Scan.ParallelScan
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-segpk-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    written = [{"PutRequest": {"Item": {"pk": {"S": pk}, "sk": {"S": sk}}}}
               for pk in _PKS for sk in _SKS]
    _batch_write(ddb, table, written)
    all_keys = {(pk, sk) for pk in _PKS for sk in _SKS}

    per_segment = {seg: _scan_segment(ddb, table, seg) for seg in range(_TOTAL_SEGMENTS)}
    flat = [(it["pk"]["S"], it["sk"]["S"]) for seg in per_segment for it in per_segment[seg]]
    assert sorted(flat) == sorted(all_keys), (
        f"the union of the {_TOTAL_SEGMENTS} segments must equal every written (pk, sk) exactly "
        f"once; symmetric difference {sorted(set(flat) ^ all_keys)[:20]!r}"
    )

    pk_to_segments: dict[str, set[int]] = {}
    for seg, items in per_segment.items():
        for item in items:
            pk_to_segments.setdefault(item["pk"]["S"], set()).add(seg)

    split = {pk: sorted(segs) for pk, segs in pk_to_segments.items() if len(segs) != 1}
    assert not split, (
        f"every sort key under one partition key must come back from exactly one Segment; "
        f"{len(split)!r} partition key(s) split across segments: {split!r}"
    )
    assert set(pk_to_segments) == set(_PKS), (
        f"expected all {len(_PKS)!r} partition keys to appear, got {sorted(pk_to_segments)!r}"
    )

    for pk in _PKS:
        got = {it["sk"]["S"] for seg in per_segment.values() for it in seg if it["pk"]["S"] == pk}
        assert got == set(_SKS), (
            f"partition key {pk!r} must return all {len(_SKS)!r} of its sort keys from its single "
            f"segment, got {sorted(got)!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
