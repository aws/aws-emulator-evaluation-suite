"""delete-item-write-capacity-billed-on-deleted-item-size."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-item-write-capacity-billed-on-deleted-item-size"
GROUP = "capacity"
SERVICES = ["dynamodb"]


def _item(pk: str, raw_len: int) -> dict:
    """"pk"(2)+pk(3)+"v"(1)+raw_len bytes of string value."""
    return {"pk": {"S": pk}, "v": {"S": "x" * raw_len}}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteItem's write capacity is billed on the size of the item it deletes: a 1024-byte item
    costs 1 write capacity unit and a 1025-byte item costs 2, not a flat per-call charge.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-delsz-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    at_boundary = _item("k01", 1018)  # "pk"(2)+"k01"(3)+"v"(1)+1018 = 1024 bytes
    ddb.put_item(TableName=table, Item=at_boundary)
    cc_at = ddb.delete_item(
        TableName=table, Key={"pk": {"S": "k01"}}, ReturnConsumedCapacity="TOTAL",
    )["ConsumedCapacity"]
    assert cc_at["CapacityUnits"] == 1.0, (
        f"deleting a 1024-byte item must cost 1.0 write capacity unit, got {cc_at['CapacityUnits']!r}"
    )
    assert ddb.get_item(TableName=table, Key={"pk": {"S": "k01"}}, ConsistentRead=True).get("Item") is None, (
        "the deleted 1024-byte item must be gone"
    )

    over_boundary = _item("k02", 1019)  # one byte over the boundary -> 1025 bytes
    ddb.put_item(TableName=table, Item=over_boundary)
    cc_over = ddb.delete_item(
        TableName=table, Key={"pk": {"S": "k02"}}, ReturnConsumedCapacity="TOTAL",
    )["ConsumedCapacity"]
    assert cc_over["CapacityUnits"] == 2.0, (
        f"deleting a 1025-byte item must cost 2.0 write capacity units, got {cc_over['CapacityUnits']!r}"
    )
    assert ddb.get_item(TableName=table, Key={"pk": {"S": "k02"}}, ConsistentRead=True).get("Item") is None, (
        "the deleted 1025-byte item must be gone"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
