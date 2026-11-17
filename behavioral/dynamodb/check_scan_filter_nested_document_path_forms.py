"""scan-filter-nested-document-path-forms."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-nested-document-path-forms"
GROUP = "expressions"
SERVICES = ["dynamodb"]

#: KEEP matches every filter below; SKIP matches none, proving each filter selects by its own
#: nested path rather than by accident.
_KEEP = {
    "pk": {"S": "keep"},
    "info": {"M": {"status": {"S": "accepted"}}},
    "steps": {"L": [{"M": {"child": {"S": "p"}}}, {"M": {"child": {"S": "q"}}}]},
    "box": {"M": {"other": {"S": "x"}}},
    "lvl1": {"M": {"lvl2": {"M": {"lvl3": {"S": "target"}}}}},
    "doc": {"M": {"big": {"S": "abcdef"}}},
}
_SKIP = {
    "pk": {"S": "skip"},
    "info": {"M": {"status": {"S": "declined"}}},
    "steps": {"L": [{"M": {"child": {"S": "z"}}}]},
    "box": {"M": {"child": {"S": "present"}}},
    "lvl1": {"M": {"lvl2": {"M": {"lvl3": {"S": "other"}}}}},
    "doc": {"M": {"big": {"S": "ab"}}},
}


def _scan_pks(ddb, table, filter_expression, names, values) -> set:
    """The set of ``pk`` values a Scan returns under one FilterExpression."""
    kwargs = {"ExpressionAttributeNames": names} if names else {}
    if values:
        kwargs["ExpressionAttributeValues"] = values
    resp = ddb.scan(
        TableName=table, ConsistentRead=True,
        FilterExpression=filter_expression,
        **kwargs,
    )
    return {i["pk"]["S"] for i in resp["Items"]}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression selects by a nested document path: begins_with through an
    aliased reserved-word segment, a list-index-then-map-key path, attribute_not_exists on an
    absent nested map child, equality three levels deep, and size() of a nested string.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-ddbnp-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    resp = ddb.batch_write_item(RequestItems={table: [
        {"PutRequest": {"Item": _KEEP}}, {"PutRequest": {"Item": _SKIP}},
    ]})
    assert resp["UnprocessedItems"] == {}, (
        f"seeding BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed"
    )

    # begins_with through an aliased nested path whose segment ("status") is a reserved word.
    names = {"#i": "info", "#s": "status"}
    got = _scan_pks(ddb, table, "begins_with(#i.#s, :p)", names, {":p": {"S": "acc"}})
    assert got == {"keep"}, f"begins_with(info.status, 'acc') selected {sorted(got)!r}, expected ['keep']"
    none = _scan_pks(ddb, table, "begins_with(#i.#s, :p)", names, {":p": {"S": "xyz"}})
    assert none == set(), f"begins_with(info.status, 'xyz') selected {sorted(none)!r}, expected none"

    # list-index then map-key: steps[0].child.
    got = _scan_pks(ddb, table, "steps[0].child = :v", {}, {":v": {"S": "p"}})
    assert got == {"keep"}, f"steps[0].child = 'p' selected {sorted(got)!r}, expected ['keep']"

    # attribute_not_exists on an absent nested map child.
    names = {"#b": "box", "#c": "child"}
    got = _scan_pks(ddb, table, "attribute_not_exists(#b.#c)", names, {})
    assert got == {"keep"}, f"attribute_not_exists(box.child) selected {sorted(got)!r}, expected ['keep']"

    # equality three levels deep.
    got = _scan_pks(ddb, table, "lvl1.lvl2.lvl3 = :v", {}, {":v": {"S": "target"}})
    assert got == {"keep"}, f"lvl1.lvl2.lvl3 = 'target' selected {sorted(got)!r}, expected ['keep']"

    # size() of a nested document path.
    got = _scan_pks(ddb, table, "size(doc.big) = :n", {}, {":n": {"N": "6"}})
    assert got == {"keep"}, f"size(doc.big) = 6 selected {sorted(got)!r}, expected ['keep']"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
