"""gsi-scan-filter-expression-parenthesized-or-under-and."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "gsi-scan-filter-expression-parenthesized-or-under-and"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_INDEX = "category-index"

#: Six records as (id, category, status, flagged). Every expected set is derived from these at
#: run time. item-005 is the control: status=new with flagged=False, so the parenthesized grouping
#: excludes it (the AND on #f applies to the whole OR group) but the unparenthesized precedence
#: `#s = :s1 OR (#s = :s2 AND #f = :yes)` matches it on the OR leg alone.
_ROWS = (
    ("item-001", "books", "new", True),
    ("item-002", "books", "used", True),
    ("item-003", "toys", "new", True),
    ("item-004", "toys", "used", False),
    ("item-005", "games", "new", False),
    ("item-006", "games", "used", False),
)


def _item(row: tuple) -> dict:
    rid, category, status, flagged = row
    return {"id": {"S": rid}, "category": {"S": category}, "status": {"S": status},
            "flagged": {"BOOL": flagged}}


def _seed(ctx) -> str:
    """A fresh id-keyed table, with a category GSI, seeded with the six records."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbgsiparen-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "id", "AttributeType": "S"},
            {"AttributeName": "category", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [{"AttributeName": "category", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    resp = ddb.batch_write_item(RequestItems={name: [{"PutRequest": {"Item": _item(r)}} for r in _ROWS]})
    assert resp["UnprocessedItems"] == {}, (
        f"seeding BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed"
    )
    _wait_index_active(ddb, name)
    _wait_index_caught_up(ddb, name)
    return name


def _wait_index_active(ddb, name: str) -> None:
    """Poll the table description until the GSI reaches ACTIVE."""
    deadline = time.monotonic() + 180
    while True:
        gsis = ddb.describe_table(TableName=name)["Table"].get("GlobalSecondaryIndexes", [])
        statuses = {g["IndexName"]: g["IndexStatus"] for g in gsis}
        if statuses.get(_INDEX) == "ACTIVE":
            return
        assert time.monotonic() < deadline, f"index {_INDEX!r} did not reach ACTIVE: {statuses!r}"
        time.sleep(2)


def _wait_index_caught_up(ddb, name: str) -> None:
    """Poll the index scan's ScannedCount until replication has carried over every seed row."""
    deadline = time.monotonic() + 60
    while True:
        scanned = ddb.scan(TableName=name, IndexName=_INDEX, Select="COUNT")["ScannedCount"]
        if scanned == len(_ROWS):
            return
        assert time.monotonic() < deadline, (
            f"index {_INDEX!r} ScannedCount stuck at {scanned!r}, expected {len(_ROWS)!r}"
        )
        time.sleep(1)


def _ids(items) -> list:
    return sorted(i["id"]["S"] for i in items)


def _index_scan(ddb, name: str, filter_expr: str) -> tuple:
    """Every page of a Scan over the category index; (ids, Count sum, ScannedCount sum)."""
    names = {"#s": "status", "#f": "flagged"}
    values = {":s1": {"S": "new"}, ":s2": {"S": "used"}, ":yes": {"BOOL": True}}
    items, count, scanned, start = [], 0, 0, None
    while True:
        extra = {"ExclusiveStartKey": start} if start else {}
        page = ddb.scan(TableName=name, IndexName=_INDEX, FilterExpression=filter_expr,
                        ExpressionAttributeNames=names, ExpressionAttributeValues=values, **extra)
        items.extend(page["Items"])
        count += page["Count"]
        scanned += page["ScannedCount"]
        start = page.get("LastEvaluatedKey")
        if not start:
            return _ids(items), count, scanned


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI Scan's FilterExpression honors an explicit `(#s = :s1 OR #s = :s2) AND #f = :yes`
    grouping, which selects a different set than the unparenthesized OR/AND precedence.
    """
    ddb = ctx.client("dynamodb")
    name = _seed(ctx)

    grouped_ids, grouped_count, grouped_scanned = _index_scan(
        ddb, name, "(#s = :s1 OR #s = :s2) AND #f = :yes"
    )
    expected = sorted(r[0] for r in _ROWS if r[2] in ("new", "used") and r[3])
    assert grouped_ids == expected, (
        f"'(#s = :s1 OR #s = :s2) AND #f = :yes' on the category index returned {grouped_ids!r}, "
        f"expected {expected!r}; the unparenthesized precedence "
        f"'#s = :s1 OR (#s = :s2 AND #f = :yes)' would also include item-006"
    )
    assert (grouped_count, grouped_scanned) == (len(expected), len(_ROWS)), (
        f"the grouped index scan reported Count {grouped_count!r} / ScannedCount {grouped_scanned!r}, "
        f"expected {len(expected)} / {len(_ROWS)} (every row sits in the index, since category is "
        f"never absent)"
    )

    unparenthesized_ids, _c, _s = _index_scan(ddb, name, "#s = :s1 OR #s = :s2 AND #f = :yes")
    expected_loose = sorted(
        r[0] for r in _ROWS if r[2] == "new" or (r[2] == "used" and r[3])
    )
    assert unparenthesized_ids == expected_loose, (
        f"'#s = :s1 OR #s = :s2 AND #f = :yes' (AND binds tighter, no parens) returned "
        f"{unparenthesized_ids!r}, expected {expected_loose!r}"
    )
    assert unparenthesized_ids != grouped_ids, (
        f"the parenthesized and unparenthesized forms returned the same set {grouped_ids!r}; "
        f"the seed cannot tell the two parses apart"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
