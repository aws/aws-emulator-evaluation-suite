"""scan-filter-expression-not-and-per-comparison-parens."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-expression-not-and-per-comparison-parens"
GROUP = "expressions"
SERVICES = ["dynamodb"]

#: Five records as (id, status, category). Every expected set is derived from these at run time.
_ROWS = (
    ("item-001", "active", "premium"),
    ("item-002", "inactive", "basic"),
    ("item-003", "pending", "basic"),
    ("item-004", "active", "basic"),
    ("item-005", "suspended", "premium"),
)


def _item(row: tuple) -> dict:
    rid, status, category = row
    return {"id": {"S": rid}, "status": {"S": status}, "category": {"S": category}}


def _seed(ctx) -> str:
    """A fresh id-keyed table seeded with the five records in one BatchWriteItem."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbparen-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    resp = ddb.batch_write_item(RequestItems={name: [{"PutRequest": {"Item": _item(r)}} for r in _ROWS]})
    assert resp["UnprocessedItems"] == {}, (
        f"seeding BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed"
    )
    return name


def _ids(items) -> list:
    return sorted(i["id"]["S"] for i in items)


def _scan(ddb, name: str, filter_expr: str) -> list:
    names = {"#s": "status", "#c": "category"}
    values = {":a": {"S": "active"}, ":b": {"S": "basic"}}
    items, start = [], None
    while True:
        extra = {"ExclusiveStartKey": start} if start else {}
        page = ddb.scan(TableName=name, FilterExpression=filter_expr, ConsistentRead=True,
                        ExpressionAttributeNames=names, ExpressionAttributeValues=values, **extra)
        items.extend(page["Items"])
        start = page.get("LastEvaluatedKey")
        if not start:
            return items


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression groups a NOT comparison in its own parentheses, and groups
    each AND operand in its own parentheses, each matching its unparenthesized equivalent.
    """
    ddb = ctx.client("dynamodb")
    name = _seed(ctx)

    not_in_group = _ids(_scan(ddb, name, "(NOT #s = :a) AND #c = :b"))
    expected_tight = sorted(r[0] for r in _ROWS if r[1] != "active" and r[2] == "basic")
    assert not_in_group == expected_tight, (
        f"'(NOT #s = :a) AND #c = :b' returned {not_in_group!r}, expected {expected_tight!r}"
    )

    not_in_group_both_grouped = _ids(_scan(ddb, name, "(NOT #s = :a) AND (#c = :b)"))
    assert not_in_group_both_grouped == expected_tight, (
        f"'(NOT #s = :a) AND (#c = :b)' returned {not_in_group_both_grouped!r}, "
        f"expected {expected_tight!r}"
    )

    per_comparison = _ids(_scan(ddb, name, "(#s = :a) AND (#c = :b)"))
    expected_and = sorted(r[0] for r in _ROWS if r[1] == "active" and r[2] == "basic")
    assert per_comparison == expected_and, (
        f"'(#s = :a) AND (#c = :b)' returned {per_comparison!r}, expected {expected_and!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
