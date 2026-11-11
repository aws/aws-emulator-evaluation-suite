"""lsi-query-pagination-over-tied-index-sort-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lsi-query-pagination-over-tied-index-sort-key"
GROUP = "lsi"
SERVICES = ["dynamodb"]

_INDEX = "lsi1"
_RANKS = (1, 2, 3)
_LIMITS = (1, 2, 3, 5, 7)


def _read(ddb, table, forward, limit=None):
    """Every item of partition p0 on the LSI, following LastEvaluatedKey; returns (items, page sizes, LEKs)."""
    kwargs = {
        "TableName": table, "IndexName": _INDEX, "KeyConditionExpression": "pk = :p",
        "ExpressionAttributeValues": {":p": {"S": "p0"}}, "ScanIndexForward": forward,
        "ConsistentRead": True,
    }
    if limit is not None:
        kwargs["Limit"] = limit
    items, page_sizes, leks = [], [], []
    while True:
        resp = ddb.query(**kwargs)
        items.extend(resp["Items"])
        page_sizes.append(len(resp["Items"]))
        lek = resp.get("LastEvaluatedKey")
        if lek is None:
            return items, page_sizes, leks
        leks.append(lek)
        assert len(leks) <= 40, f"LSI query paging did not end after 40 pages: {leks!r}"
        kwargs["ExclusiveStartKey"] = lek


def _keys(items):
    return [(it["pk"]["S"], it["sk"]["S"]) for it in items]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Limit walk of an LSI Query over items tied on the index sort key returns every item
    exactly once in the same order as an unpaged read, and each LastEvaluatedKey names exactly
    the table key plus the LSI sort key.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LSI.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-lsitie-")
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

    # 12 items in partition p0: three distinct lsk values, each shared by four items.
    expected = set()
    for i in range(12):
        sk = f"s{i:02d}"
        ddb.put_item(TableName=table, Item={
            "pk": {"S": "p0"}, "sk": {"S": sk}, "lsk": {"N": str(_RANKS[i % 3])},
        })
        expected.add(("p0", sk))
    # A second partition proves the tie-break stays scoped to p0.
    ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": "s00"}, "lsk": {"N": "1"}})

    forward, _, _ = _read(ddb, table, True)
    fkeys = _keys(forward)
    assert len(fkeys) == len(expected) and set(fkeys) == expected, (
        f"unpaged LSI query returned {fkeys!r}, expected each of {sorted(expected)!r} once"
    )
    rank_seq = [int(it["lsk"]["N"]) for it in forward]
    want_ranks = [r for r in sorted(_RANKS) for _ in range(4)]
    assert rank_seq == want_ranks, f"LSI sort-key order {rank_seq!r}, expected grouped order {want_ranks!r}"

    backward = _keys(_read(ddb, table, False)[0])
    assert backward == list(reversed(fkeys)), (
        f"ScanIndexForward=False {backward!r} is not the mirror of forward {fkeys!r}"
    )

    for limit in _LIMITS:
        for direction, unpaged in ((True, fkeys), (False, backward)):
            items, page_sizes, leks = _read(ddb, table, direction, limit)
            walk = _keys(items)
            assert walk == unpaged, (
                f"Limit={limit} forward={direction} walk {walk!r} != unpaged {unpaged!r}"
            )
            assert max(page_sizes) <= limit and len(leks) >= 1, (
                f"Limit={limit} forward={direction} page sizes {page_sizes!r} did not page as expected"
            )
            for lek in leks:
                assert set(lek) == {"pk", "sk", "lsk"}, (
                    f"LastEvaluatedKey {lek!r} must name exactly pk, sk and lsk"
                )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
