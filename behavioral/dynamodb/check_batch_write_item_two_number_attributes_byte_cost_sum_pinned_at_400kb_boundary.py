"""batch-write-item-two-number-attributes-byte-cost-sum-pinned-at-400kb-boundary."""
from __future__ import annotations

from decimal import Decimal

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-two-number-attributes-byte-cost-sum-pinned-at-400kb-boundary"
GROUP = "limits"
SERVICES = ["dynamodb"]
LIMIT_BYTES = 409600
_SIZE_ERR = ("ValidationException", "Item size has exceeded the maximum allowed size")

# Two large-exponent Numbers at the documented magnitude ceiling, one of each sign; each cost is
# the exact byte count a binary search over the item size limit measures for that literal alone.
_N1 = "9.9999999999999999999999999999999999999E+125"
_N2 = "-9.9999999999999999999999999999999999999E+125"
_N1_COST = 20
_N2_COST = 21
_N1_STORED = format(Decimal(_N1), "f")
_N2_STORED = format(Decimal(_N2), "f")


def _item_of_total_size(pk_value: str, total_bytes: int) -> dict:
    """A pk + two N attributes (byte cost _N1_COST, _N2_COST) + filler item sized to total_bytes."""
    overhead = len("pk") + len(pk_value) + len("n1") + _N1_COST + len("n2") + _N2_COST + len("f")
    filler_len = total_bytes - overhead
    assert filler_len > 0, f"{total_bytes} bytes is too small for this item's fixed attributes"
    return {
        "pk": {"S": pk_value},
        "n1": {"N": _N1},
        "n2": {"N": _N2},
        "f": {"S": "x" * filler_len},
    }


def expect_error(fn, code, message) -> None:
    """Assert ``fn`` raises exactly (code, message); an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == code, (
            f"expected {code}, got {err.get('Code')}: {err.get('Message')!r}"
        )
        assert err.get("Message") == message, (
            f"expected AWS's exact message {message!r}, got {err.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchWriteItem sums the byte cost of two Number attributes in one item: an item built
    from two large-exponent Numbers at exactly 400 KB passes, and one byte over is refused with
    the item size error, writing nothing.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 30})

    def get(pk):
        return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")

    # --- at exactly 400 KB: accepted, and both Numbers round-trip in their canonical stored form ---
    at_limit = _item_of_total_size("at-limit", LIMIT_BYTES)
    resp = ddb.batch_write_item(RequestItems={table: [{"PutRequest": {"Item": at_limit}}]})
    assert resp.get("UnprocessedItems", {}) == {}, (
        f"a {LIMIT_BYTES}-byte item split across two Number attributes must fully process, "
        f"got UnprocessedItems={resp.get('UnprocessedItems')!r}"
    )
    got = get("at-limit")
    assert got["n1"] == {"N": _N1_STORED}, f"n1 must round-trip as {_N1_STORED!r}, got {got['n1']}"
    assert got["n2"] == {"N": _N2_STORED}, f"n2 must round-trip as {_N2_STORED!r}, got {got['n2']}"
    assert got["f"]["S"] == at_limit["f"]["S"], "the filler must read back whole at exactly the limit"

    # --- one byte over, split the same way across the same two Numbers: refused, nothing written ---
    over = _item_of_total_size("over-limit", LIMIT_BYTES + 1)
    expect_error(
        lambda: ddb.batch_write_item(RequestItems={table: [{"PutRequest": {"Item": over}}]}),
        *_SIZE_ERR,
    )
    assert get("over-limit") is None, (
        "a BatchWriteItem PutRequest rejected for size must not persist the item"
    )

    # Positive control: the table still accepts an ordinary write after the rejection.
    ddb.batch_write_item(RequestItems={table: [
        {"PutRequest": {"Item": {"pk": {"S": "ctrl"}, "n1": {"N": "1"}}}},
    ]})
    assert get("ctrl")["n1"] == {"N": "1"}, "control write after the rejection must still succeed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
