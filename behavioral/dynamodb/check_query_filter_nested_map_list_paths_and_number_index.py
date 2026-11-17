"""query-filter-nested-map-list-paths-and-number-index."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-nested-map-list-paths-and-number-index"
GROUP = "expressions"
SERVICES = ["dynamodb"]

#: Five sort keys under one partition, as (sk, has_child, leaf, list_child, num1).
#: ``has_child`` controls whether ``meta`` carries a ``child`` member; ``leaf`` is the
#: three-level path ``deep.mid.leaf``; ``list_child`` is ``items[0].child``; ``num1`` is
#: the Number stored at ``nums[1]``.
_ROWS = (
    ("a", True, "L1", "x", "5"),
    ("b", False, "L2", "y", "7"),
    ("c", True, "L1", "x", "5"),
    ("d", False, "L1", "y", "5"),
    ("e", True, "L2", "x", "7"),
)


def _item(row) -> dict:
    sk, has_child, leaf, list_child, num1 = row
    meta = {"child": {"S": "yes"}} if has_child else {"other": {"S": "1"}}
    return {
        "pk": {"S": "grp"}, "sk": {"S": sk},
        "meta": {"M": meta},
        "deep": {"M": {"mid": {"M": {"leaf": {"S": leaf}}}}},
        "items": {"L": [{"M": {"child": {"S": list_child}}}, {"S": "tail"}]},
        "nums": {"L": [{"N": "0"}, {"N": num1}, {"N": "99"}]},
    }


def _seed(ctx) -> str:
    """A fresh pk='grp' table with the five rows, under one BatchWriteItem."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbqfn-")
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
    resp = ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="pk = :p",
        FilterExpression=filter_expression,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues={":p": {"S": "grp"}, **values},
    )
    return {i["sk"]["S"] for i in resp["Items"]}


@tags("axis:happy-path", "cap:c2", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query's FilterExpression resolves attribute_exists/attribute_not_exists, equality and a
    list-index child on a nested document path, and a three-level map path and a list[i]
    holding a Number, each selecting the exact items that hold it.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.Attributes.html
    """
    ddb = ctx.client("dynamodb")
    table = _seed(ctx)
    has_child = {r[0] for r in _ROWS if r[1]}
    no_child = {r[0] for r in _ROWS if not r[1]}
    names = {"#m": "meta", "#c": "child"}

    got = _query(ddb, table, "attribute_exists(#m.#c)", names, {})
    assert got == has_child, (
        f"attribute_exists(meta.child) returned {sorted(got)!r}, expected {sorted(has_child)!r}"
    )

    got = _query(ddb, table, "attribute_not_exists(#m.#c)", names, {})
    assert got == no_child, (
        f"attribute_not_exists(meta.child) returned {sorted(got)!r}, expected {sorted(no_child)!r}"
    )

    want_leaf = {r[0] for r in _ROWS if r[2] == "L1"}
    got = _query(ddb, table, "#d.#mi.#l = :l1", {"#d": "deep", "#mi": "mid", "#l": "leaf"},
                 {":l1": {"S": "L1"}})
    assert got == want_leaf, (
        f"three-level nested path deep.mid.leaf = 'L1' returned {sorted(got)!r}, "
        f"expected {sorted(want_leaf)!r}"
    )

    want_list_child = {r[0] for r in _ROWS if r[3] == "x"}
    got = _query(ddb, table, "#i[0].#c = :x", {"#i": "items", "#c": "child"}, {":x": {"S": "x"}})
    assert got == want_list_child, (
        f"items[0].child = 'x' returned {sorted(got)!r}, expected {sorted(want_list_child)!r}"
    )

    want_num = {r[0] for r in _ROWS if r[4] == "5"}
    got = _query(ddb, table, "#n[1] = :n5", {"#n": "nums"}, {":n5": {"N": "5"}})
    assert got == want_num, f"nums[1] = 5 returned {sorted(got)!r}, expected {sorted(want_num)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
