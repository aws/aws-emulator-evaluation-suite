"""query-filter-expression-parentheses-and-document-paths."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-expression-parentheses-and-document-paths"
GROUP = "expressions"
SERVICES = ["dynamodb"]

#: Five sort keys under one partition, as (sk, status, category, tags, meta_created).
#: ``meta_created`` is None where the item's ``meta`` map omits the ``created`` key.
_ROWS = (
    ("a", "active", "A", ["x", "y"], "2024"),
    ("b", "pending", "B", ["z"], None),
    ("c", "active", "B", ["x"], "2025"),
    ("d", "inactive", "A", ["y", "x"], None),
    ("e", "active", "C", [], "2024"),
)


def _item(row) -> dict:
    sk, status, category, tags_, meta_created = row
    meta = {"created": {"S": meta_created}} if meta_created is not None else {"other": {"S": "1"}}
    return {
        "pk": {"S": "grp"}, "sk": {"S": sk},
        "status": {"S": status}, "category": {"S": category},
        "tags": {"L": [{"S": v} for v in tags_]}, "meta": {"M": meta},
    }


def _seed(ctx) -> str:
    """A fresh pk='grp' table with the five rows, under one BatchWriteItem."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbqfp-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                   {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    resp = ddb.batch_write_item(RequestItems={name: [{"PutRequest": {"Item": _item(r)}} for r in _ROWS]})
    assert resp["UnprocessedItems"] == {}, (
        f"seeding BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed"
    )
    return name


def _query(ddb, table, filter_expression, names, values) -> set:
    """The set of ``sk`` values a Query against ``table`` returns under one filter form."""
    kwargs = {"ExpressionAttributeNames": names} if names else {}
    resp = ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="pk = :p",
        FilterExpression=filter_expression,
        ExpressionAttributeValues={":p": {"S": "grp"}, **values},
        **kwargs,
    )
    return {i["sk"]["S"] for i in resp["Items"]}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query's FilterExpression parses a full-wrap, a nested grouping, per-condition
    parens and a parenthesized function call the same way Scan's does, and a nested
    map path or list-index operand, parenthesized or not, selects the same items.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = _seed(ctx)
    names = {"#s": "status", "#c": "category"}

    full_wrap = {r[0] for r in _ROWS if r[1] == "active" and r[2] == "B"}
    got = _query(ddb, table, "(#s = :active AND #c = :catB)", names,
                 {":active": {"S": "active"}, ":catB": {"S": "B"}})
    assert got == full_wrap, f"full-wrap AND returned {sorted(got)!r}, expected {sorted(full_wrap)!r}"

    nested = {r[0] for r in _ROWS if (r[1] == "pending" or r[2] == "A") and r[2] == "B"}
    got = _query(ddb, table, "(#s = :pending OR #c = :catA) AND #c = :catB", names,
                 {":pending": {"S": "pending"}, ":catA": {"S": "A"}, ":catB": {"S": "B"}})
    assert got == nested, f"nested grouping returned {sorted(got)!r}, expected {sorted(nested)!r}"

    per_condition = {r[0] for r in _ROWS if r[1] == "active" and r[2] == "C"}
    got = _query(ddb, table, "(#s = :active) AND (#c = :catC)", names,
                 {":active": {"S": "active"}, ":catC": {"S": "C"}})
    assert got == per_condition, (
        f"per-condition parens returned {sorted(got)!r}, expected {sorted(per_condition)!r}"
    )

    starts_with_a = {r[0] for r in _ROWS if r[2].startswith("A")}
    got = _query(ddb, table, "(begins_with(#c, :pfx))", {"#c": "category"}, {":pfx": {"S": "A"}})
    assert got == starts_with_a, (
        f"parenthesized begins_with returned {sorted(got)!r}, expected {sorted(starts_with_a)!r}"
    )

    created_2024 = {r[0] for r in _ROWS if r[4] == "2024"}
    got = _query(ddb, table, "meta.created = :y", {}, {":y": {"S": "2024"}})
    assert got == created_2024, (
        f"nested map path returned {sorted(got)!r}, expected {sorted(created_2024)!r}"
    )
    got = _query(ddb, table, "(meta.created = :y)", {}, {":y": {"S": "2024"}})
    assert got == created_2024, (
        f"parenthesized nested map path returned {sorted(got)!r}, expected {sorted(created_2024)!r}"
    )

    first_tag_x = {r[0] for r in _ROWS if r[3][:1] == ["x"]}
    got = _query(ddb, table, "tags[0] = :x", {}, {":x": {"S": "x"}})
    assert got == first_tag_x, f"list-index path returned {sorted(got)!r}, expected {sorted(first_tag_x)!r}"
    got = _query(ddb, table, "(tags[0] = :x)", {}, {":x": {"S": "x"}})
    assert got == first_tag_x, (
        f"parenthesized list-index path returned {sorted(got)!r}, expected {sorted(first_tag_x)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
