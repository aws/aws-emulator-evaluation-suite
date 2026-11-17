"""batch-get-item-consumed-capacity-itemizes-per-table-and-charges-absent-keys."""
from __future__ import annotations

import math

from behavioral_harness import tags

CHECK = "batch-get-item-consumed-capacity-itemizes-per-table-and-charges-absent-keys"
GROUP = "capacity"
SERVICES = ["dynamodb"]

_KB = 1024
_RCU_BLOCK = 4 * _KB
_SMALL_BAND = 1 * _KB
_LARGE_BAND = 5 * _KB


def _pad_for(band: int, pk: str) -> str:
    """Padding that lands the whole item just inside `band` bytes.

    Overhead accounted for: the "pk" name (2) + its value, and the "pad" name (3).
    """
    return "x" * (band - 2 - len(pk) - 3)


def _simple_table(ctx, ddb, prefix: str) -> str:
    name = ctx.unique_name(prefix)
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=name: ddb.delete_table(TableName=n))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single BatchGetItem spanning two tables returns one ConsumedCapacity entry per table,
    each still rounding its own items to 4KB blocks and charging a key that misses exactly like a
    key that hits; INDEXES reports the same per-table total under Table.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html
    """
    ddb = ctx.client("dynamodb")
    table_a = _simple_table(ctx, ddb, "sim2real-behav-ddbmcap-a-")
    table_b = _simple_table(ctx, ddb, "sim2real-behav-ddbmcap-b-")

    present_a, present_b, absent_b = "present", "present", "absent"

    put_a = ddb.put_item(TableName=table_a, Item={"pk": {"S": present_a},
                                                  "pad": {"S": _pad_for(_SMALL_BAND, present_a)}},
                         ReturnConsumedCapacity="TOTAL")
    wcu_a = put_a["ConsumedCapacity"]["CapacityUnits"]
    assert wcu_a == _SMALL_BAND / _KB, (
        f"the canary write of the {_SMALL_BAND}-byte item on table_a billed {wcu_a!r} WCU, "
        f"expected {_SMALL_BAND / _KB!r} -- the read assertions below rest on this item actually "
        f"being that size"
    )
    put_b = ddb.put_item(TableName=table_b, Item={"pk": {"S": present_b},
                                                  "pad": {"S": _pad_for(_LARGE_BAND, present_b)}},
                         ReturnConsumedCapacity="TOTAL")
    wcu_b = put_b["ConsumedCapacity"]["CapacityUnits"]
    assert wcu_b == _LARGE_BAND / _KB, (
        f"the canary write of the {_LARGE_BAND}-byte item on table_b billed {wcu_b!r} WCU, "
        f"expected {_LARGE_BAND / _KB!r} -- the read assertions below rest on this item actually "
        f"being that size"
    )

    a_blocks = math.ceil(_SMALL_BAND / _RCU_BLOCK)
    b_blocks = math.ceil(_LARGE_BAND / _RCU_BLOCK) + 1  # the present item's own blocks, plus one for the absent key

    for rcc in ("TOTAL", "INDEXES"):
        for consistent, factor in ((False, 0.5), (True, 1.0)):
            resp = ddb.batch_get_item(
                RequestItems={
                    table_a: {"Keys": [{"pk": {"S": present_a}}], "ConsistentRead": consistent},
                    table_b: {"Keys": [{"pk": {"S": present_b}}, {"pk": {"S": absent_b}}],
                             "ConsistentRead": consistent},
                },
                ReturnConsumedCapacity=rcc,
            )
            unprocessed = resp.get("UnprocessedKeys") or {}
            assert not unprocessed, (
                f"{rcc} consistent={consistent} BatchGetItem left UnprocessedKeys {unprocessed!r}; "
                f"its capacity numbers therefore cover fewer than both tables' keys and cannot be "
                f"compared"
            )
            assert resp["Responses"][table_a] == [{"pk": {"S": present_a},
                                                    "pad": {"S": _pad_for(_SMALL_BAND, present_a)}}], (
                f"table_a's Responses entry was {resp['Responses'][table_a]!r}, expected only the "
                f"present item"
            )
            assert resp["Responses"][table_b] == [{"pk": {"S": present_b},
                                                    "pad": {"S": _pad_for(_LARGE_BAND, present_b)}}], (
                f"table_b's Responses entry was {resp['Responses'][table_b]!r}, expected only the "
                f"present item -- the absent key must be omitted, never reported as unprocessed"
            )

            consumed = resp["ConsumedCapacity"]
            by_table = {entry["TableName"]: entry for entry in consumed}
            assert len(consumed) == 2 and set(by_table) == {table_a, table_b}, (
                f"{rcc} consistent={consistent} ConsumedCapacity must carry exactly one entry per "
                f"table in the request, got {consumed!r}"
            )

            expected_a = a_blocks * factor
            expected_b = b_blocks * factor
            got_a = by_table[table_a]["CapacityUnits"]
            got_b = by_table[table_b]["CapacityUnits"]
            assert got_a == expected_a, (
                f"{rcc} consistent={consistent}: table_a (one {_SMALL_BAND}-byte item) billed "
                f"{got_a!r}, expected {expected_a!r}"
            )
            assert got_b == expected_b, (
                f"{rcc} consistent={consistent}: table_b (one {_LARGE_BAND}-byte item plus one "
                f"absent key) billed {got_b!r}, expected {expected_b!r} -- a key that misses must "
                f"still round up and charge its own 4KB block, exactly like a key that hits"
            )

            if rcc == "INDEXES":
                got_a_table = by_table[table_a]["Table"]["CapacityUnits"]
                got_b_table = by_table[table_b]["Table"]["CapacityUnits"]
                assert got_a_table == got_a, (
                    f"INDEXES table_a Table.CapacityUnits was {got_a_table!r}, expected it to equal "
                    f"the entry's own total {got_a!r}"
                )
                assert got_b_table == got_b, (
                    f"INDEXES table_b Table.CapacityUnits was {got_b_table!r}, expected it to equal "
                    f"the entry's own total {got_b!r}"
                )

    # Positive control: the absent key alone, read directly with GetItem, bills exactly the one
    # block that its contribution to the batch above assumed.
    solo_absent = ddb.get_item(TableName=table_b, Key={"pk": {"S": absent_b}}, ConsistentRead=True,
                               ReturnConsumedCapacity="TOTAL")
    assert "Item" not in solo_absent, f"the absent key unexpectedly has an item: {solo_absent!r}"
    solo_cu = solo_absent["ConsumedCapacity"]["CapacityUnits"]
    assert solo_cu == 1.0, (
        f"a strongly consistent GetItem on the absent key alone billed {solo_cu!r}, expected 1.0 "
        f"(one full block, the same charge a miss costs when reached through BatchGetItem)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
