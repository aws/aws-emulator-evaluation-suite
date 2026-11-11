"""query-gsi-four-range-key-schema-orders-narrows-and-reverses."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-gsi-four-range-key-schema-orders-narrows-and-reverses"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_INDEX = "by-four-range"
_RANGE = ["gsk1", "gsk2", "gsk3", "gsk4"]

# (pk, gsk1, gsk2, gsk3, gsk4); every RANGE position differs across the set, and p1/p2 share
# every attribute but gsk4 so a prefix can narrow all the way down to a two-item range.
_ITEMS = [
    ("p1", "eng", "api", "ic", "2023"),
    ("p2", "eng", "api", "ic", "2024"),
    ("p3", "eng", "api", "mgr", "2023"),
    ("p4", "eng", "web", "ic", "2023"),
    ("p5", "eng", "web", "mgr", "2024"),
    ("p6", "ops", "api", "ic", "2023"),
    ("p7", "ops", "api", "mgr", "2023"),
    ("p8", "ops", "web", "mgr", "2024"),
]


def _poll(ctx, read, want):
    """read() every 2 s until it equals want, bounded by the run budget."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 120.0) - 20.0)
    while True:
        value = read()
        if value == want or time.monotonic() >= deadline:
            return value
        time.sleep(2)


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table and its indexes are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI keyed on one HASH and four RANGE attributes orders a HASH-only Query by the RANGE
    attributes in schema order (reversed under ScanIndexForward=false), narrows under a 1-3
    attribute equality prefix or a range condition right after one, free of clause order.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-gsi4r-")
    key_schema = [{"AttributeName": "gpk", "KeyType": "HASH"}] + [
        {"AttributeName": n, "KeyType": "RANGE"} for n in _RANGE
    ]
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ["pk", "gpk", *_RANGE]],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": key_schema,
            "Projection": {"ProjectionType": "ALL"},
        }],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    desc = _wait_active(ddb, ctx, table)
    described = desc["GlobalSecondaryIndexes"][0]["KeySchema"]
    assert described == key_schema, f"the GSI describes its key as {described!r}"

    for pk, g1, g2, g3, g4 in _ITEMS:
        ddb.put_item(TableName=table, Item={
            "pk": {"S": pk}, "gpk": {"S": "g1"},
            "gsk1": {"S": g1}, "gsk2": {"S": g2}, "gsk3": {"S": g3}, "gsk4": {"S": g4},
        })

    def query(cond, values, *, forward=True):
        pages = ddb.get_paginator("query").paginate(
            TableName=table, IndexName=_INDEX, KeyConditionExpression=cond,
            ExpressionAttributeValues=values, ScanIndexForward=forward,
        )
        items = [i for page in pages for i in page["Items"]]
        return [i["pk"]["S"] for i in items]

    all_pks = [row[0] for row in _ITEMS]

    # A HASH-only query orders by the RANGE attributes in schema order (gsk1, gsk2, gsk3, gsk4).
    got = _poll(ctx, lambda: query("gpk = :g", {":g": {"S": "g1"}}), all_pks)
    assert got == all_pks, f"the HASH-only query returned {got!r}, expected schema order {all_pks!r}"

    # ScanIndexForward=false reverses that same order.
    want = list(reversed(all_pks))
    got = _poll(ctx, lambda: query("gpk = :g", {":g": {"S": "g1"}}, forward=False), want)
    assert got == want, f"ScanIndexForward=false returned {got!r}"

    # A 1-attribute equality prefix (gsk1) narrows to that subset, still ordered by gsk2..gsk4.
    want = ["p1", "p2", "p3", "p4", "p5"]
    got = _poll(ctx, lambda: query(
        "gpk = :g AND gsk1 = :v1", {":g": {"S": "g1"}, ":v1": {"S": "eng"}},
    ), want)
    assert got == want, f"the gsk1 equality prefix returned {got!r}"

    # A 2-attribute equality prefix (gsk1, gsk2) narrows further.
    want = ["p1", "p2", "p3"]
    got = _poll(ctx, lambda: query(
        "gpk = :g AND gsk1 = :v1 AND gsk2 = :v2",
        {":g": {"S": "g1"}, ":v1": {"S": "eng"}, ":v2": {"S": "api"}},
    ), want)
    assert got == want, f"the gsk1+gsk2 equality prefix returned {got!r}"

    # A 3-attribute equality prefix (gsk1, gsk2, gsk3) narrows to the pair sharing every
    # attribute but gsk4.
    want = ["p1", "p2"]
    got = _poll(ctx, lambda: query(
        "gpk = :g AND gsk1 = :v1 AND gsk2 = :v2 AND gsk3 = :v3",
        {":g": {"S": "g1"}, ":v1": {"S": "eng"}, ":v2": {"S": "api"}, ":v3": {"S": "ic"}},
    ), want)
    assert got == want, f"the gsk1+gsk2+gsk3 equality prefix returned {got!r}"

    # A range condition on the attribute right after a 1-attribute prefix (position two, gsk2):
    # a "<" comparator on gsk2 narrows the same way the gsk2 equality prefix above did.
    want = ["p1", "p2", "p3"]
    got = _poll(ctx, lambda: query(
        "gpk = :g AND gsk1 = :v1 AND gsk2 < :v2",
        {":g": {"S": "g1"}, ":v1": {"S": "eng"}, ":v2": {"S": "web"}},
    ), want)
    assert got == want, f"a '<' condition on gsk2 after the gsk1 prefix returned {got!r}"

    # A range condition on the attribute right after a 3-attribute prefix (position four, gsk4):
    # begins_with narrows the pair down to the one item whose gsk4 matches the prefix.
    want = ["p1"]
    got = _poll(ctx, lambda: query(
        "gpk = :g AND gsk1 = :v1 AND gsk2 = :v2 AND gsk3 = :v3 AND begins_with(gsk4, :v4)",
        {":g": {"S": "g1"}, ":v1": {"S": "eng"}, ":v2": {"S": "api"}, ":v3": {"S": "ic"}, ":v4": {"S": "2023"}},
    ), want)
    assert got == want, f"begins_with on gsk4 after the gsk1+gsk2+gsk3 prefix returned {got!r}"

    # The same position-four range, expressed as BETWEEN, selects the same single item.
    want = ["p1"]
    got = _poll(ctx, lambda: query(
        "gpk = :g AND gsk1 = :v1 AND gsk2 = :v2 AND gsk3 = :v3 AND gsk4 BETWEEN :lo AND :hi",
        {":g": {"S": "g1"}, ":v1": {"S": "eng"}, ":v2": {"S": "api"}, ":v3": {"S": "ic"},
         ":lo": {"S": "2020"}, ":hi": {"S": "2023"}},
    ), want)
    assert got == want, f"BETWEEN on gsk4 after the gsk1+gsk2+gsk3 prefix returned {got!r}"

    # Clause order in KeyConditionExpression does not matter: the position-four BETWEEN query
    # above, with every clause reordered, selects the same item.
    want = ["p1"]
    got = _poll(ctx, lambda: query(
        "gsk4 BETWEEN :lo AND :hi AND gsk3 = :v3 AND gpk = :g AND gsk2 = :v2 AND gsk1 = :v1",
        {":g": {"S": "g1"}, ":v1": {"S": "eng"}, ":v2": {"S": "api"}, ":v3": {"S": "ic"},
         ":lo": {"S": "2020"}, ":hi": {"S": "2023"}},
    ), want)
    assert got == want, f"reordering the clauses changed the result to {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
