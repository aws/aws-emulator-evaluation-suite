"""batch-write-item-rounds-each-item-to-1kb-then-sums."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-rounds-each-item-to-1kb-then-sums"
GROUP = "capacity"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _item_of_size(pk_value: str, filler_attr: str, total_bytes: int) -> dict:
    """A one-pk, one-filler-attribute item whose aggregate encoded size is exactly total_bytes."""
    overhead = len("pk") + len(pk_value) + len(filler_attr)
    filler_len = total_bytes - overhead
    assert filler_len > 0, f"{total_bytes} bytes is too small for this item shape"
    return {"pk": {"S": pk_value}, filler_attr: {"S": "x" * filler_len}}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchWriteItem rounds each PutRequest item up to its own 1 KB boundary before summing:
    a 500-byte put plus a 3584-byte (3.5 KB) put in one call cost 5 write units together, not
    the 4 units that rounding their combined 4084 bytes once would give.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CapacityUnitCalculations.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-bwcu-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 30})

    # Positive controls: each size alone, rounded up on its own, costs its own documented unit count.
    small = _item_of_size("ctrl-small", "f", 500)
    small_resp = ddb.put_item(TableName=table, Item=small, ReturnConsumedCapacity="TOTAL")
    small_cu = small_resp["ConsumedCapacity"]["CapacityUnits"]
    assert small_cu == 1.0, f"a lone 500-byte PutItem consumed {small_cu!r} CapacityUnits, expected 1.0"

    big = _item_of_size("ctrl-big", "f", 3584)
    big_resp = ddb.put_item(TableName=table, Item=big, ReturnConsumedCapacity="TOTAL")
    big_cu = big_resp["ConsumedCapacity"]["CapacityUnits"]
    assert big_cu == 4.0, f"a lone 3584-byte PutItem consumed {big_cu!r} CapacityUnits, expected 4.0"

    # The subject: both sizes in ONE BatchWriteItem call against the same table.
    batch_small = _item_of_size("batch-small", "f", 500)
    batch_big = _item_of_size("batch-big", "f", 3584)
    batch_resp = ddb.batch_write_item(
        RequestItems={table: [
            {"PutRequest": {"Item": batch_small}},
            {"PutRequest": {"Item": batch_big}},
        ]},
        ReturnConsumedCapacity="TOTAL",
    )
    assert batch_resp.get("UnprocessedItems", {}) == {}, (
        f"the two-item batch must be accepted whole, got UnprocessedItems="
        f"{batch_resp.get('UnprocessedItems')!r}"
    )
    cc = batch_resp["ConsumedCapacity"]
    assert len(cc) == 1, f"expected one per-table capacity entry, got {cc!r}"
    assert cc[0]["TableName"] == table, (
        f"the capacity entry named table {cc[0]['TableName']!r}, expected {table!r}"
    )
    batch_cu = cc[0]["CapacityUnits"]
    assert batch_cu == 5.0, (
        f"a batch of a 500-byte put and a 3584-byte put consumed {batch_cu!r} CapacityUnits, "
        f"expected 5.0: each item rounds up to its own 1 KB boundary (1.0 + 4.0) before the "
        f"table total sums them, rather than rounding their combined 4084 bytes once"
    )

    got_small = ddb.get_item(
        TableName=table, Key={"pk": {"S": "batch-small"}}, ConsistentRead=True
    ).get("Item", {})
    assert got_small.get("f", {}).get("S") == batch_small["f"]["S"], (
        f"the 500-byte batched item must round-trip whole, got "
        f"{len(got_small.get('f', {}).get('S', ''))} bytes back"
    )
    got_big = ddb.get_item(
        TableName=table, Key={"pk": {"S": "batch-big"}}, ConsistentRead=True
    ).get("Item", {})
    assert got_big.get("f", {}).get("S") == batch_big["f"]["S"], (
        f"the 3584-byte batched item must round-trip whole, got "
        f"{len(got_big.get('f', {}).get('S', ''))} bytes back"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
