"""scan-filter-list-index-paths-under-or-and-attribute-type-on-nested-paths."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-list-index-paths-under-or-and-attribute-type-on-nested-paths"
GROUP = "data-plane"
SERVICES = ["dynamodb"]

#: Five items as (id, tags list, meta.created typed value or None for "meta has no created key").
_ROWS = (
    ("i1", ["x", "y"], ("S", "2024")),
    ("i2", ["y", "x"], ("N", "5")),
    ("i3", ["z"], ("BOOL", True)),
    ("i4", [], ("S", "2024")),
    ("i5", ["y"], None),
)


def _item(row) -> dict:
    rid, tag_list, created = row
    meta = {"created": {created[0]: created[1]}} if created else {"other": {"S": "1"}}
    return {
        "id": {"S": rid},
        "tags": {"L": [{"S": v} for v in tag_list]},
        "meta": {"M": meta},
    }


def _seed(ctx) -> str:
    """A fresh table with the five rows, under one BatchWriteItem."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbsfl-")
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


def _scan_all(ddb, table: str, **kwargs) -> list:
    """Every item of a strongly consistent Scan, across pages."""
    items, start = [], None
    while True:
        extra = {"ExclusiveStartKey": start} if start else {}
        page = ddb.scan(TableName=table, ConsistentRead=True, **kwargs, **extra)
        items.extend(page["Items"])
        start = page.get("LastEvaluatedKey")
        if not start:
            return items


def _ids(items) -> set:
    return {i["id"]["S"] for i in items}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Scan's FilterExpression ORs two list-index document paths into one match set, and
    attribute_type resolves the exact stored type at a nested map leaf and at a list index.
    """
    ddb = ctx.client("dynamodb")
    table = _seed(ctx)

    baseline = _ids(_scan_all(ddb, table))
    assert baseline == {r[0] for r in _ROWS}, (
        f"the unfiltered Scan returned {sorted(baseline)!r}, expected every seeded id"
    )

    def tag_at(row, index):
        return row[1][index] if len(row[1]) > index else None

    or_match = {r[0] for r in _ROWS if tag_at(r, 0) == "x" or tag_at(r, 1) == "x"}
    got = _ids(_scan_all(
        ddb, table,
        FilterExpression="tags[0] = :x OR tags[1] = :x",
        ExpressionAttributeValues={":x": {"S": "x"}},
    ))
    assert got == or_match, f"the OR'd list-index filter returned {sorted(got)!r}, expected {sorted(or_match)!r}"

    for type_name, want_value in (("S", "2024"), ("N", None), ("BOOL", None)):
        expected = {r[0] for r in _ROWS if r[2] is not None and r[2][0] == type_name}
        got = _ids(_scan_all(
            ddb, table,
            FilterExpression="attribute_type(meta.created, :t)",
            ExpressionAttributeValues={":t": {"S": type_name}},
        ))
        assert got == expected, (
            f"attribute_type(meta.created, {type_name!r}) returned {sorted(got)!r}, expected {sorted(expected)!r}"
        )

    list_index_type_match = {r[0] for r in _ROWS if tag_at(r, 0) is not None}
    got = _ids(_scan_all(
        ddb, table,
        FilterExpression="attribute_type(tags[0], :t)",
        ExpressionAttributeValues={":t": {"S": "S"}},
    ))
    assert got == list_index_type_match, (
        f"attribute_type(tags[0], 'S') returned {sorted(got)!r}, expected {sorted(list_index_type_match)!r}"
    )

    got_item = ddb.get_item(TableName=table, Key={"id": {"S": "i3"}}, ConsistentRead=True)["Item"]
    assert got_item == _item(_ROWS[2]), f"GetItem i3 returned {got_item!r}, expected {_item(_ROWS[2])!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
