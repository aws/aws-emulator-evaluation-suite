"""put-item-consumed-capacity-pins-1024-byte-boundary-and-overwrite-follows-larger-image."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-item-consumed-capacity-pins-1024-byte-boundary-and-overwrite-follows-larger-image"
GROUP = "capacity"
SERVICES = ["dynamodb"]

# Item size = sum of (attribute name bytes + value bytes), key attributes included.
# "pk"(2) + "k"(1) + "v"(1) + X = 4 + X -> X=1020 totals exactly 1024 B; X=1021 totals exactly 1025 B.
_AT_1024 = "x" * 1020
_AT_1025 = "y" * 1021


def _units(resp, label):
    cc = resp.get("ConsumedCapacity")
    assert cc is not None, f"{label}: no ConsumedCapacity although ReturnConsumedCapacity was set: {resp!r}"
    return cc.get("CapacityUnits")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A 1024-byte PutItem costs 1 WCU and a 1025-byte one costs 2; overwriting the 1025-byte
    item with a 1024-byte one still costs 2, the larger of the two images either side of the write.
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
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    key = {"pk": {"S": "k"}}

    create = ddb.put_item(
        TableName=table, Item={"pk": {"S": "k"}, "v": {"S": _AT_1024}},
        ReturnConsumedCapacity="TOTAL",
    )
    u = _units(create, "PutItem creating the exact 1024-byte item")
    assert u == 1.0, f"a 1024-byte item with no prior image consumed {u!r} WCU; expected 1.0"

    created = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item") or {}
    assert created.get("v", {}).get("S") == _AT_1024, "the 1024-byte item must read back whole"

    grow = ddb.put_item(
        TableName=table, Item={"pk": {"S": "k"}, "v": {"S": _AT_1025}},
        ReturnConsumedCapacity="TOTAL",
    )
    u = _units(grow, "PutItem overwriting the 1024-byte item with a 1025-byte one")
    assert u == 2.0, f"overwriting a 1024-byte item with a 1025-byte one consumed {u!r} WCU; expected 2.0"

    grown = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item") or {}
    assert grown.get("v", {}).get("S") == _AT_1025, "the 1025-byte overwrite must persist"

    shrink = ddb.put_item(
        TableName=table, Item={"pk": {"S": "k"}, "v": {"S": _AT_1024}},
        ReturnConsumedCapacity="TOTAL",
    )
    u = _units(shrink, "PutItem overwriting the 1025-byte item with a 1024-byte one")
    assert u == 2.0, (
        f"overwriting a 1025-byte item with a 1024-byte one consumed {u!r} WCU; expected 2.0 "
        f"(the larger, pre-write image). 1.0 means it was metered on the post-write size alone."
    )

    shrunk = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item") or {}
    assert shrunk.get("v", {}).get("S") == _AT_1024, "the shrink overwrite must persist the 1024-byte image"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
