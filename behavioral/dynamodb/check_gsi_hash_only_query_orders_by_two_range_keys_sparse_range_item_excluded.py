"""gsi-hash-only-query-orders-by-two-range-keys-sparse-range-item-excluded."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-hash-only-query-orders-by-two-range-keys-sparse-range-item-excluded"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_INDEX = "by-group"

# (pk, gsk1, gsk2); p4 carries gsk1 but not gsk2, so it is missing one of the index's two RANGE
# attributes and must be excluded from the index entirely, not merely unordered within it.
_FULL_ITEMS = [
    ("p1", "a", "x"),
    ("p2", "a", "y"),
    ("p3", "b", "x"),
    ("p5", "c", "y"),
]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_active(ddb, table, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table)["Table"]
        indexes = last.get("GlobalSecondaryIndexes", [])
        if last["TableStatus"] == "ACTIVE" and indexes and all(
            g.get("IndexStatus") == "ACTIVE" for g in indexes
        ):
            return
        time.sleep(3)
    raise AssertionError(f"table {table} or its GSI did not become ACTIVE: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A HASH-only Query of a GSI keyed on one HASH and two RANGE attributes orders its items by
    the RANGE attributes in schema order, and excludes an item missing either one."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-gsi1h2r-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "gpk", "AttributeType": "S"},
            {"AttributeName": "gsk1", "AttributeType": "S"},
            {"AttributeName": "gsk2", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [
                {"AttributeName": "gpk", "KeyType": "HASH"},
                {"AttributeName": "gsk1", "KeyType": "RANGE"},
                {"AttributeName": "gsk2", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)
    desc = ddb.describe_table(TableName=table)["Table"]
    key_schema = desc["GlobalSecondaryIndexes"][0]["KeySchema"]
    assert key_schema == [
        {"AttributeName": "gpk", "KeyType": "HASH"},
        {"AttributeName": "gsk1", "KeyType": "RANGE"},
        {"AttributeName": "gsk2", "KeyType": "RANGE"},
    ], f"the GSI describes its key as {key_schema!r}"

    for pk, gsk1, gsk2 in _FULL_ITEMS:
        ddb.put_item(TableName=table, Item={
            "pk": {"S": pk}, "gpk": {"S": "g1"}, "gsk1": {"S": gsk1}, "gsk2": {"S": gsk2},
        })
    # p4 carries the HASH attribute and gsk1, but not gsk2: a sparse write relative to the index.
    ddb.put_item(TableName=table, Item={"pk": {"S": "p4"}, "gpk": {"S": "g1"}, "gsk1": {"S": "b"}})

    def query():
        pages = ddb.get_paginator("query").paginate(
            TableName=table, IndexName=_INDEX, KeyConditionExpression="gpk = :g",
            ExpressionAttributeValues={":g": {"S": "g1"}},
        )
        return [i["pk"]["S"] for page in pages for i in page["Items"]]

    want = ["p1", "p2", "p3", "p5"]
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 60.0)
    while True:
        got = query()
        if got == want or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert got == want, (
        f"the HASH-only query returned {got!r}, expected the four fully-keyed items ordered by "
        f"(gsk1, gsk2) in schema order {want!r}, with the sparse item p4 excluded"
    )

    def scan_gsi():
        pages = ddb.get_paginator("scan").paginate(TableName=table, IndexName=_INDEX)
        return sorted(i["pk"]["S"] for page in pages for i in page["Items"])

    indexed = scan_gsi()
    assert indexed == sorted(want), (
        f"a Scan of the GSI returned {indexed!r}, expected exactly {sorted(want)!r}"
    )
    assert "p4" not in indexed, (
        f"p4, which lacks the index's gsk2 RANGE attribute, was indexed anyway: {indexed!r}"
    )

    # p4 is a genuine table row even though the GSI never indexed it: GetItem on the base table
    # by the table's own primary key still returns it.
    base = ddb.get_item(TableName=table, Key={"pk": {"S": "p4"}}, ConsistentRead=True)["Item"]
    assert base["gsk1"] == {"S": "b"} and "gsk2" not in base, (
        f"base-table GetItem on p4 returned {base!r}, expected gsk1='b' and no gsk2"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
