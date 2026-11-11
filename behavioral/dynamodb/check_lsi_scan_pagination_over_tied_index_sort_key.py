"""lsi-scan-pagination-over-tied-index-sort-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lsi-scan-pagination-over-tied-index-sort-key"
GROUP = "lsi"
SERVICES = ["dynamodb"]

_INDEX = "lsi1"
_RANKS = (1, 2, 3)


def _scan(ddb, table, limit=None):
    """Every item on the LSI via Scan, following LastEvaluatedKey; returns (items, page sizes, LEKs)."""
    kwargs = {"TableName": table, "IndexName": _INDEX, "ConsistentRead": True}
    if limit is not None:
        kwargs["Limit"] = limit
    items, page_sizes, leks = [], [], []
    while True:
        resp = ddb.scan(**kwargs)
        items.extend(resp["Items"])
        page_sizes.append(len(resp["Items"]))
        lek = resp.get("LastEvaluatedKey")
        if lek is None:
            return items, page_sizes, leks
        leks.append(lek)
        assert len(leks) <= 40, f"LSI scan paging did not end after 40 pages: {leks!r}"
        kwargs["ExclusiveStartKey"] = lek


def _keys(items):
    return [(it["pk"]["S"], it["sk"]["S"]) for it in items]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Limit walk of an LSI Scan over a partition tied on the index sort key returns every item
    exactly once in the same order as an unpaged scan, and each LastEvaluatedKey names exactly
    the table key plus the LSI sort key.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LSI.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-lsiscantie-")
    ddb.create_table(
        TableName=table,
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

    # Partition p0: 12 items, three distinct lsk values, each shared by four items.
    expected = set()
    for i in range(12):
        sk = f"s{i:02d}"
        ddb.put_item(TableName=table, Item={
            "pk": {"S": "p0"}, "sk": {"S": sk}, "lsk": {"N": str(_RANKS[i % 3])},
        })
        expected.add(("p0", sk))
    # A second, untied partition proves cross-partition dedup still holds.
    for i in range(3):
        sk = f"s{i:02d}"
        ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": sk}, "lsk": {"N": str(i)}})
        expected.add(("p1", sk))

    unpaged, _, _ = _scan(ddb, table)
    ukeys = _keys(unpaged)
    assert len(ukeys) == len(expected) and set(ukeys) == expected, (
        f"unpaged LSI scan returned {ukeys!r}, expected each of {sorted(expected)!r} once"
    )
    again = _keys(_scan(ddb, table)[0])
    assert again == ukeys, f"repeated unpaged LSI scan changed order: {ukeys!r} then {again!r}"

    p0_ranks = [int(it["lsk"]["N"]) for it in unpaged if it["pk"]["S"] == "p0"]
    want_ranks = [r for r in sorted(_RANKS) for _ in range(4)]
    assert p0_ranks == want_ranks, (
        f"partition p0's LSI sort-key order {p0_ranks!r}, expected grouped order {want_ranks!r}"
    )

    for limit in (1, 2, 3, 5, 7, 10):
        items, page_sizes, leks = _scan(ddb, table, limit)
        walk = _keys(items)
        assert walk == ukeys, f"Limit={limit} walk {walk!r} != unpaged {ukeys!r}"
        assert max(page_sizes) <= limit and len(leks) >= 1, (
            f"Limit={limit} page sizes {page_sizes!r} did not page as expected"
        )
        for lek in leks:
            assert set(lek) == {"pk", "sk", "lsk"}, (
                f"LastEvaluatedKey {lek!r} must name exactly pk, sk and lsk"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
