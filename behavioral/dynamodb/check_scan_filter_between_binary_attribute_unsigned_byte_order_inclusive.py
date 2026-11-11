"""scan-filter-between-binary-attribute-unsigned-byte-order-inclusive."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-between-binary-attribute-unsigned-byte-order-inclusive"
GROUP = "data-plane"
SERVICES = ["dynamodb"]

# Five one-byte Binary values spanning the signed/unsigned boundary at 0x80. Every expected set
# below is derived from this seed at run time, never hardcoded.
_ROWS = (
    ("item0", b"\x00"),
    ("item1", b"\x01"),
    ("item2", b"\x7f"),
    ("item3", b"\x80"),
    ("item4", b"\xff"),
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression BETWEEN on a Binary attribute compares unsigned bytes and
    includes both bounds: 0x80 ranks above 0x01, which a signed comparison would invert.
    """
    ddb = ctx.client("dynamodb")
    table = _seed(ctx, ddb)

    def want(lo: bytes, hi: bytes) -> list:
        return sorted(rid for rid, val in _ROWS if lo <= val <= hi)

    cases = (
        (b"\x01", b"\x80"),  # spans the signed/unsigned boundary; only valid in unsigned order
        (b"\x80", b"\xff"),  # both bounds in the "negative" half under a signed reading
        (b"\x00", b"\xff"),  # the full range: every item, both bounds inclusive
        (b"\x01", b"\x7f"),  # neither bound touches the boundary byte
    )
    sizes = [len(want(lo, hi)) for lo, hi in cases]
    assert sizes == [3, 2, 5, 2], f"the seed-derived expectations moved: {sizes!r}"

    for lo, hi in cases:
        got = _ids(_scan_all(ddb, TableName=table, FilterExpression="bin BETWEEN :lo AND :hi",
                             ExpressionAttributeValues={":lo": {"B": lo}, ":hi": {"B": hi}}))
        expected = want(lo, hi)
        assert got == expected, (
            f"bin BETWEEN {lo!r} AND {hi!r} returned {got!r}, expected {expected!r}"
        )

    # Positive control: the exact bound values are themselves matched (inclusive on both ends).
    lo, hi = b"\x01", b"\x80"
    got = _ids(_scan_all(ddb, TableName=table, FilterExpression="bin BETWEEN :lo AND :hi",
                         ExpressionAttributeValues={":lo": {"B": lo}, ":hi": {"B": hi}}))
    assert "item1" in got and "item3" in got, (
        f"BETWEEN {lo!r} AND {hi!r} excluded an item equal to one of its own bounds: {got!r}"
    )


def _seed(ctx, ddb) -> str:
    """A fresh on-demand table keyed by `id`, seeded with the Binary rows in one BatchWriteItem."""
    table = ctx.unique_name("sim2real-ddbscb-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    items = [{"id": {"S": rid}, "bin": {"B": val}} for rid, val in _ROWS]
    resp = ddb.batch_write_item(RequestItems={table: [{"PutRequest": {"Item": i}} for i in items]})
    assert resp["UnprocessedItems"] == {}, (
        f"seeding BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed"
    )
    return table


def _ids(items) -> list:
    return sorted(i["id"]["S"] for i in items)


def _scan_all(ddb, **kw) -> list:
    """Every item of a strongly consistent scan, across pages."""
    items, start = [], None
    while True:
        extra = {"ExclusiveStartKey": start} if start else {}
        page = ddb.scan(ConsistentRead=True, **kw, **extra)
        items.extend(page["Items"])
        start = page.get("LastEvaluatedKey")
        if not start:
            return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
