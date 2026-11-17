"""lsi-scan-filter-and-limit-paging-over-tied-sort-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lsi-scan-filter-and-limit-paging-over-tied-sort-key"
GROUP = "lsi"
SERVICES = ["dynamodb"]

_INDEX = "lsi1"
_LIMIT = 10

#: 20 items in one partition, five distinct LSI sort-key values each shared by four items
#: (ties), category alternating within each tied group so the filter cannot follow sort order.
_ITEMS = tuple(
    {
        "pk": {"S": "p0"},
        "sk": {"S": f"s{i:02d}"},
        "lsk": {"N": str(i // 4)},
        "category": {"S": "even" if i % 2 == 0 else "odd"},
    }
    for i in range(20)
)
_EVEN_KEYS = tuple(sorted(it["sk"]["S"] for it in _ITEMS if it["category"]["S"] == "even"))


def _scan_all_pages(ddb, **kwargs):
    """Every page of a Scan, following LastEvaluatedKey; returns (items, per-page ScannedCount, LEKs)."""
    items, scanned_counts, leks = [], [], []
    kw = dict(kwargs)
    while True:
        page = ddb.scan(**kw)
        items.extend(page.get("Items", []))
        scanned_counts.append(page["ScannedCount"])
        lek = page.get("LastEvaluatedKey")
        if lek is None:
            return items, scanned_counts, leks
        leks.append(lek)
        assert len(leks) <= 40, f"LSI scan paging did not end after 40 pages: {leks!r}"
        kw["ExclusiveStartKey"] = lek


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Limit=10 FilterExpression Scan of an LSI over a partition tied on the index sort key
    returns every matching item exactly once, paging on ScannedCount rather than match count.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Query.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-lsifilim-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "lsk", "AttributeType": "N"},
        ],
        LocalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "lsk", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for item in _ITEMS:
        ddb.put_item(TableName=table, Item=item)

    unfiltered, unfiltered_scanned, unfiltered_leks = _scan_all_pages(
        ddb, TableName=table, IndexName=_INDEX, ConsistentRead=True, Limit=_LIMIT,
    )
    all_keys = tuple(sorted(it["sk"]["S"] for it in _ITEMS))
    unfiltered_keys = tuple(sorted(it["sk"]["S"] for it in unfiltered))
    assert unfiltered_keys == all_keys and len(unfiltered) == len(_ITEMS), (
        f"unfiltered Limit={_LIMIT} LSI scan returned {unfiltered_keys!r}, expected every "
        f"written item exactly once"
    )
    assert (unfiltered_scanned, len(unfiltered_leks)) == ([_LIMIT, _LIMIT, 0], 2), (
        f"unfiltered Limit={_LIMIT} LSI scan of {len(_ITEMS)} items paged ScannedCounts "
        f"{unfiltered_scanned!r} with {len(unfiltered_leks)} LastEvaluatedKey(s), expected "
        f"[{_LIMIT}, {_LIMIT}, 0] with 2"
    )

    filtered, filtered_scanned, filtered_leks = _scan_all_pages(
        ddb, TableName=table, IndexName=_INDEX, ConsistentRead=True, Limit=_LIMIT,
        FilterExpression="category = :c", ExpressionAttributeValues={":c": {"S": "even"}},
    )
    got_keys = tuple(sorted(it["sk"]["S"] for it in filtered))
    assert got_keys == _EVEN_KEYS and len(filtered) == len(_EVEN_KEYS), (
        f"filtered Limit={_LIMIT} LSI scan over tied sort keys returned {got_keys!r}, "
        f"expected {_EVEN_KEYS!r}"
    )
    for it in filtered:
        assert it["category"] == {"S": "even"}, f"a non-matching item leaked through the filter: {it!r}"
    assert (filtered_scanned, len(filtered_leks)) == ([_LIMIT, _LIMIT, 0], 2), (
        f"filtered Limit={_LIMIT} LSI scan paged ScannedCounts {filtered_scanned!r} with "
        f"{len(filtered_leks)} LastEvaluatedKey(s), expected [{_LIMIT}, {_LIMIT}, 0] with 2: "
        f"Limit counts examined items, not matches"
    )
    for lek in filtered_leks:
        assert set(lek) == {"pk", "sk", "lsk"}, (
            f"LastEvaluatedKey {lek!r} must name exactly pk, sk and lsk"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
