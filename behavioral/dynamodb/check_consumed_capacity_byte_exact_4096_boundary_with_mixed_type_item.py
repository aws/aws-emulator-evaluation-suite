"""consumed-capacity-byte-exact-4096-boundary-with-mixed-type-item."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "consumed-capacity-byte-exact-4096-boundary-with-mixed-type-item"
GROUP = "capacity"
SERVICES = ["dynamodb"]

_ITEM_LIMIT = 409600
ERR_VALIDATION = "ValidationException"
ERR_OVERSIZED = "Item size has exceeded the maximum allowed size"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; the resource's own not-found
    code means it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _fixed_item(pk: str) -> dict:
    """A representative mixed-type item: N, B, BOOL, NULL, L and M members."""
    return {
        "pk": {"S": pk},
        "n": {"N": "42"},
        "b": {"B": b"\x01\x02\x03\x04"},
        "bo": {"BOOL": True},
        "nu": {"NULL": True},
        "l": {"L": [{"S": "ab"}, {"B": b"\x05\x06"}, {"BOOL": False}]},
        "m": {"M": {"x": {"S": "y"}, "z": {"NULL": True}}},
    }


def _fits(ddb, table: str, pk: str, filler_len: int) -> bool:
    """PutItem of the fixed mixed-type item plus an ``f`` filler of ``filler_len`` bytes.

    True if accepted; False if rejected for exceeding the item size limit. Any other error is a
    defect in the check, not an expected outcome, and is left to raise.
    """
    item = _fixed_item(pk)
    item["f"] = {"S": "x" * filler_len}
    try:
        ddb.put_item(TableName=table, Item=item)
        return True
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == ERR_VALIDATION, (
            f"oversized PutItem: expected {ERR_VALIDATION!r}, got {err.get('Code')!r}: "
            f"{err.get('Message')!r}"
        )
        assert err.get("Message") == ERR_OVERSIZED, (
            f"oversized PutItem: expected the exact message {ERR_OVERSIZED!r}, got "
            f"{err.get('Message')!r}"
        )
        return False


def _search(ddb, table: str, pk: str, lo: int, hi: int) -> int:
    """Binary search for the largest filler length in [lo, hi], given lo fits and hi+1 does not."""
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if _fits(ddb, table, pk, mid):
            lo = mid
        else:
            hi = mid - 1
    return lo


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A GetItem's CapacityUnits is 1.0 strong / 0.5 eventual for an item of exactly 4096 bytes
    and 2.0 / 1.0 for 4097, with the size built from N, B, BOOL, NULL, L and M members.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CapacityUnitCalculations.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-rcub-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    pk = "k"
    # The fixed N/B/BOOL/NULL/L/M attributes plus `pk` have a byte cost this check does not
    # compute by hand: a Number's documented cost is only "approximately" one byte per two
    # significant digits, so the exact figure is measured against the item size ceiling -- a hard
    # byte-exact boundary -- instead of assumed from the approximation.
    assert _fits(ddb, table, pk, 0), "the fixed mixed-type item alone must already fit under 400KB"
    assert not _fits(ddb, table, pk, _ITEM_LIMIT), (
        f"the fixed mixed-type item plus a {_ITEM_LIMIT!r}-byte filler must already exceed 400KB"
    )
    max_filler = _search(ddb, table, pk, 0, _ITEM_LIMIT)
    # max_filler fits and max_filler + 1 does not, so the item at max_filler is exactly 409600
    # bytes; everything but the filler's own bytes is the remainder.
    fixed_bytes = _ITEM_LIMIT - max_filler

    target_4096 = 4096 - fixed_bytes
    target_4097 = target_4096 + 1
    assert target_4096 >= 0, (
        f"the fixed mixed-type item alone is {fixed_bytes!r} bytes, which already exceeds the "
        f"4096-byte block this check means to land on"
    )

    def _put(filler_len: int) -> None:
        item = _fixed_item(pk)
        item["f"] = {"S": "x" * filler_len}
        ddb.put_item(TableName=table, Item=item)

    def _capacity(*, consistent: bool) -> float:
        resp = ddb.get_item(
            TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=consistent,
            ReturnConsumedCapacity="TOTAL",
        )
        assert "Item" in resp, "the item must exist before its capacity can be read"
        return resp["ConsumedCapacity"]["CapacityUnits"]

    _put(target_4096)
    strong = _capacity(consistent=True)
    assert strong == 1.0, (
        f"a strongly consistent GetItem of the {fixed_bytes!r}+{target_4096!r}=4096-byte "
        f"mixed-type item cost {strong!r} CapacityUnits, expected 1.0"
    )
    eventual = _capacity(consistent=False)
    assert eventual == 0.5, (
        f"an eventually consistent GetItem of the same 4096-byte item cost {eventual!r} "
        f"CapacityUnits, expected 0.5"
    )

    _put(target_4097)
    strong_over = _capacity(consistent=True)
    assert strong_over == 2.0, (
        f"a strongly consistent GetItem of the {fixed_bytes!r}+{target_4097!r}=4097-byte "
        f"mixed-type item cost {strong_over!r} CapacityUnits, expected 2.0 -- one byte over the "
        f"4096-byte edge must already round up to a second block"
    )
    eventual_over = _capacity(consistent=False)
    assert eventual_over == 1.0, (
        f"an eventually consistent GetItem of the same 4097-byte item cost {eventual_over!r} "
        f"CapacityUnits, expected 1.0"
    )

    # Positive control: every mixed-type member reads back exactly as written at the larger size,
    # proving the capacity numbers above price a real item and not an absent or truncated one.
    got = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
    assert got["n"] == {"N": "42"}, f"the Number member read back as {got['n']!r}, expected N '42'"
    assert got["b"] == {"B": b"\x01\x02\x03\x04"}, f"the Binary member read back as {got['b']!r}"
    assert got["bo"] == {"BOOL": True}, f"the Boolean member read back as {got['bo']!r}"
    assert got["nu"] == {"NULL": True}, f"the Null member read back as {got['nu']!r}"
    assert got["l"] == {"L": [{"S": "ab"}, {"B": b"\x05\x06"}, {"BOOL": False}]}, (
        f"the List member read back as {got['l']!r}"
    )
    assert got["m"] == {"M": {"x": {"S": "y"}, "z": {"NULL": True}}}, (
        f"the Map member read back as {got['m']!r}"
    )
    assert len(got["f"]["S"]) == target_4097, (
        f"the filler read back {len(got['f']['S'])!r} bytes, expected {target_4097!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
