"""lsi-scan-all-and-include-projections-with-consistent-read."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lsi-scan-all-and-include-projections-with-consistent-read"
GROUP = "lsi"
SERVICES = ["dynamodb"]

_ALL_IDX = "lsi-all"
_INCLUDE_IDX = "lsi-include"

#: pk, lskA (ALL-LSI range key), lskI (INCLUDE-LSI range key), category, extra, body.
_ITEMS = tuple(
    {
        "pk": {"S": f"p{i}"},
        "sk": {"S": "fixed"},
        "lskA": {"N": str(i)},
        "lskI": {"N": str(i)},
        "category": {"S": "even" if i % 2 == 0 else "odd"},
        "extra": {"S": f"extra{i}"},
        "body": {"S": f"body{i}"},
    }
    for i in range(7)
)
_EVEN_PKS = tuple(sorted(it["pk"]["S"] for it in _ITEMS if it["category"]["S"] == "even"))


def _scan_all_pages(ddb, **kwargs) -> list:
    """Every item of a Scan, following LastEvaluatedKey."""
    items, start, guard = [], None, 0
    while True:
        kw = dict(kwargs)
        if start:
            kw["ExclusiveStartKey"] = start
        page = ddb.scan(**kw)
        items.extend(page.get("Items", []))
        start = page.get("LastEvaluatedKey")
        guard += 1
        assert guard < 50, "scan paging did not terminate"
        if not start:
            return items


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A Scan of an ALL-projection LSI returns every item attribute; a Scan of an INCLUDE-projection
    LSI returns only the key attributes plus the included one; both are ConsistentRead=True, and a
    FilterExpression with Limit paging on the ALL LSI returns exactly the matching rows.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-lsiscan-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "lskA", "AttributeType": "N"},
            {"AttributeName": "lskI", "AttributeType": "N"},
        ],
        LocalSecondaryIndexes=[
            {"IndexName": _ALL_IDX,
             "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "lskA", "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "ALL"}},
            {"IndexName": _INCLUDE_IDX,
             "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "lskI", "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["extra"]}},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for item in _ITEMS:
        ddb.put_item(TableName=table, Item=item)

    # --- ALL projection: the LSI serves every attribute of the base item ---
    all_items = ddb.scan(TableName=table, IndexName=_ALL_IDX, ConsistentRead=True)["Items"]
    assert len(all_items) == len(_ITEMS), (
        f"the ALL LSI returned {len(all_items)} item(s), expected {len(_ITEMS)}"
    )
    by_pk = {it["pk"]["S"]: it for it in all_items}
    for want in _ITEMS:
        got = by_pk.get(want["pk"]["S"])
        assert got == want, f"ALL LSI item for {want['pk']['S']!r} is {got!r}, expected {want!r}"

    # --- INCLUDE projection: the LSI serves only the key attributes plus 'extra' ---
    include_items = ddb.scan(TableName=table, IndexName=_INCLUDE_IDX, ConsistentRead=True)["Items"]
    assert len(include_items) == len(_ITEMS), (
        f"the INCLUDE LSI returned {len(include_items)} item(s), expected {len(_ITEMS)}"
    )
    for it in include_items:
        assert sorted(it) == ["extra", "lskI", "pk", "sk"], (
            f"an INCLUDE LSI must project the table key, its own range key and the named "
            f"attribute and nothing else, got {sorted(it)!r}"
        )
        expected_extra = {"S": f"extra{int(it['lskI']['N'])}"}
        assert it["extra"] == expected_extra, (
            f"the INCLUDEd attribute for lskI={it['lskI']['N']!r} is {it['extra']!r}, "
            f"expected {expected_extra!r}"
        )

    # --- FilterExpression + Limit paging on the ALL LSI returns exactly the matching rows ---
    filtered = _scan_all_pages(
        ddb, TableName=table, IndexName=_ALL_IDX, ConsistentRead=True, Limit=2,
        FilterExpression="category = :c", ExpressionAttributeValues={":c": {"S": "even"}},
    )
    got_pks = tuple(sorted(it["pk"]["S"] for it in filtered))
    assert got_pks == _EVEN_PKS, (
        f"filtered+paginated ALL LSI scan returned pks {got_pks!r}, expected {_EVEN_PKS!r}"
    )
    for it in filtered:
        assert it["category"] == {"S": "even"}, f"a non-matching item leaked through the filter: {it!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
