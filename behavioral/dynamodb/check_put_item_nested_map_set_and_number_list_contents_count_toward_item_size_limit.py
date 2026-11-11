"""put-item-nested-map-set-and-number-list-contents-count-toward-item-size-limit."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-nested-map-set-and-number-list-contents-count-toward-item-size-limit"
GROUP = "limits"
SERVICES = ["dynamodb"]

ERR_VALIDATION = "ValidationException"
_TOO_BIG_MESSAGE = "Item size has exceeded the maximum allowed size"
_DIGITS38 = "9" * 38
KB = 1024


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem counts a nested map's values, a string set's members and a Number list's
    elements toward the 400 KB item size limit, not only a top-level scalar attribute.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CapacityUnitCalculations.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-contsize-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    # Nested map: 250 sub-maps of a 2000-byte string (500,000 bytes of nested content) is
    # refused; 10 of the same shape (20,000 bytes) is accepted and reads back whole.
    def nested_map(n: int, filler_len: int) -> dict:
        entries = {f"k{i}": {"M": {"v": {"S": "x" * filler_len}}} for i in range(n)}
        return {"M": entries}

    ddb.put_item(TableName=table, Item={"pk": {"S": "nested-ok"}, "data": nested_map(10, 2000)})
    got = ddb.get_item(TableName=table, Key={"pk": {"S": "nested-ok"}}, ConsistentRead=True).get("Item", {})
    entries = got.get("data", {}).get("M", {})
    assert len(entries) == 10, f"the 10-entry nested map read back with {len(entries)!r} entries"
    assert entries["k3"]["M"]["v"]["S"] == "x" * 2000, "a nested map value did not round-trip whole"

    code, msg = _error(lambda: ddb.put_item(
        TableName=table, Item={"pk": {"S": "nested-over"}, "data": nested_map(250, 2000)}))
    assert (code, msg) == (ERR_VALIDATION, _TOO_BIG_MESSAGE), (
        f"a 500,000-byte nested map item gave {code!r}: {msg!r}"
    )
    gone = ddb.get_item(TableName=table, Key={"pk": {"S": "nested-over"}}, ConsistentRead=True)
    assert "Item" not in gone, f"the refused nested-map item was stored: {sorted(gone['Item'])!r}"

    # String set: 10 members of 4200 bytes each (42,000 bytes) is accepted and reads back
    # as the same set; 100 members of the same size (420,000 bytes) is refused.
    def string_set(n: int, member_len: int) -> list:
        return [f"{i:04d}" + "s" * (member_len - 4) for i in range(n)]

    small_set = string_set(10, 4200)
    ddb.put_item(TableName=table, Item={"pk": {"S": "ss-ok"}, "data": {"SS": small_set}})
    got = ddb.get_item(TableName=table, Key={"pk": {"S": "ss-ok"}}, ConsistentRead=True).get("Item", {})
    assert set(got.get("data", {}).get("SS", [])) == set(small_set), (
        "the 10-member string set did not round-trip whole"
    )

    big_set = string_set(100, 4200)
    code, msg = _error(lambda: ddb.put_item(TableName=table, Item={"pk": {"S": "ss-over"}, "data": {"SS": big_set}}))
    assert (code, msg) == (ERR_VALIDATION, _TOO_BIG_MESSAGE), (
        f"a 100-member, 420,000-byte string set item gave {code!r}: {msg!r}"
    )
    gone = ddb.get_item(TableName=table, Key={"pk": {"S": "ss-over"}}, ConsistentRead=True)
    assert "Item" not in gone, f"the refused string-set item was stored: {sorted(gone['Item'])!r}"

    # Number list: each 38-digit element costs 20 bytes; 15,000 of them (315,000 bytes) is
    # accepted and reads back intact; 21,000 of them (441,000 bytes) is refused.
    ddb.put_item(
        TableName=table, Item={"pk": {"S": "nlist-ok"}, "data": {"L": [{"N": _DIGITS38}] * 15_000}},
    )
    got = ddb.get_item(TableName=table, Key={"pk": {"S": "nlist-ok"}}, ConsistentRead=True).get("Item", {})
    numbers = got.get("data", {}).get("L", [])
    assert len(numbers) == 15_000, f"the stored number list reads back with {len(numbers)!r} elements"
    assert all(n == {"N": _DIGITS38} for n in numbers), "a number list element did not round-trip as the exact N string"

    code, msg = _error(lambda: ddb.put_item(
        TableName=table, Item={"pk": {"S": "nlist-over"}, "data": {"L": [{"N": _DIGITS38}] * 21_000}}))
    assert (code, msg) == (ERR_VALIDATION, _TOO_BIG_MESSAGE), (
        f"a 21,000-element 38-digit number list item gave {code!r}: {msg!r}"
    )
    gone = ddb.get_item(TableName=table, Key={"pk": {"S": "nlist-over"}}, ConsistentRead=True)
    assert "Item" not in gone, f"the refused number-list item was stored: {sorted(gone['Item'])!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
