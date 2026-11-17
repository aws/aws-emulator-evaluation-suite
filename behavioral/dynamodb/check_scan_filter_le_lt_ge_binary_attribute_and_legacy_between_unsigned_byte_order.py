"""scan-filter-le-lt-ge-binary-attribute-and-legacy-between-unsigned-byte-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-le-lt-ge-binary-attribute-and-legacy-between-unsigned-byte-order"
GROUP = "scan"
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

_BOUND = b"\x80"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression and the legacy ScanFilter compare a Binary attribute as unsigned
    bytes for <=, < and >=, and the legacy ScanFilter's BETWEEN does the same across the boundary.
    """
    ddb = ctx.client("dynamodb")
    table = _seed(ctx, ddb)

    def want_le(bound: bytes) -> list:
        return sorted(rid for rid, val in _ROWS if val <= bound)

    def want_lt(bound: bytes) -> list:
        return sorted(rid for rid, val in _ROWS if val < bound)

    def want_ge(bound: bytes) -> list:
        return sorted(rid for rid, val in _ROWS if val >= bound)

    def want_between(lo: bytes, hi: bytes) -> list:
        return sorted(rid for rid, val in _ROWS if lo <= val <= hi)

    le_expected = want_le(_BOUND)
    lt_expected = want_lt(_BOUND)
    ge_expected = want_ge(_BOUND)
    assert le_expected == ["item0", "item1", "item2", "item3"], (
        f"the seed-derived LE expectation moved: {le_expected!r}"
    )
    assert lt_expected == ["item0", "item1", "item2"], (
        f"the seed-derived LT expectation moved: {lt_expected!r}"
    )
    assert ge_expected == ["item3", "item4"], (
        f"the seed-derived GE expectation moved: {ge_expected!r}"
    )

    fe_le = _ids(_scan_all(ddb, TableName=table, FilterExpression="bin <= :v",
                           ExpressionAttributeValues={":v": {"B": _BOUND}}))
    assert fe_le == le_expected, (
        f"FilterExpression 'bin <= 0x80' returned {fe_le!r}, expected {le_expected!r} under "
        f"unsigned byte order"
    )
    legacy_le = _ids(_scan_all(ddb, TableName=table, ScanFilter={
        "bin": {"ComparisonOperator": "LE", "AttributeValueList": [{"B": _BOUND}]}}))
    assert legacy_le == fe_le, (
        f"legacy ScanFilter LE on bin returned {legacy_le!r}, must match FilterExpression's {fe_le!r}"
    )

    fe_lt = _ids(_scan_all(ddb, TableName=table, FilterExpression="bin < :v",
                           ExpressionAttributeValues={":v": {"B": _BOUND}}))
    assert fe_lt == lt_expected, (
        f"FilterExpression 'bin < 0x80' returned {fe_lt!r}, expected {lt_expected!r}: the boundary "
        f"item itself must be excluded"
    )
    legacy_lt = _ids(_scan_all(ddb, TableName=table, ScanFilter={
        "bin": {"ComparisonOperator": "LT", "AttributeValueList": [{"B": _BOUND}]}}))
    assert legacy_lt == fe_lt, (
        f"legacy ScanFilter LT on bin returned {legacy_lt!r}, must match FilterExpression's {fe_lt!r}"
    )

    fe_ge = _ids(_scan_all(ddb, TableName=table, FilterExpression="bin >= :v",
                           ExpressionAttributeValues={":v": {"B": _BOUND}}))
    assert fe_ge == ge_expected, (
        f"FilterExpression 'bin >= 0x80' returned {fe_ge!r}, expected {ge_expected!r}: 0x80 and "
        f"0xff rank above 0x7f under unsigned byte order, not below"
    )
    legacy_ge = _ids(_scan_all(ddb, TableName=table, ScanFilter={
        "bin": {"ComparisonOperator": "GE", "AttributeValueList": [{"B": _BOUND}]}}))
    assert legacy_ge == fe_ge, (
        f"legacy ScanFilter GE on bin returned {legacy_ge!r}, must match FilterExpression's {fe_ge!r}"
    )

    lo, hi = b"\x01", b"\x80"
    between_expected = want_between(lo, hi)
    assert between_expected == ["item1", "item2", "item3"], (
        f"the seed-derived BETWEEN expectation moved: {between_expected!r}"
    )
    legacy_between = _ids(_scan_all(ddb, TableName=table, ScanFilter={
        "bin": {"ComparisonOperator": "BETWEEN", "AttributeValueList": [{"B": lo}, {"B": hi}]}}))
    assert legacy_between == between_expected, (
        f"legacy ScanFilter BETWEEN 0x01..0x80 on bin returned {legacy_between!r}, expected "
        f"{between_expected!r} under unsigned byte order"
    )
    fe_between = _ids(_scan_all(ddb, TableName=table, FilterExpression="bin BETWEEN :lo AND :hi",
                                ExpressionAttributeValues={":lo": {"B": lo}, ":hi": {"B": hi}}))
    assert fe_between == legacy_between, (
        f"FilterExpression BETWEEN 0x01..0x80 returned {fe_between!r}, must match legacy "
        f"ScanFilter's {legacy_between!r}"
    )

    # Positive control: both inclusive bounds are themselves selected by LE/GE/BETWEEN.
    assert "item3" in fe_le and "item3" in fe_ge, (
        f"the boundary value 0x80 was excluded from an inclusive comparison: LE={fe_le!r} "
        f"GE={fe_ge!r}"
    )
    assert "item1" in legacy_between and "item3" in legacy_between, (
        f"BETWEEN 0x01..0x80 excluded one of its own bounds: {legacy_between!r}"
    )


def _seed(ctx, ddb) -> str:
    """A fresh on-demand table keyed by `id`, seeded with the Binary rows in one BatchWriteItem."""
    table = ctx.unique_name("sim2real-ddbscle-")
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
