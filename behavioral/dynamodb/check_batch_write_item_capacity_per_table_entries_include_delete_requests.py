"""batch-write-item-capacity-per-table-entries-include-delete-requests."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-capacity-per-table-entries-include-delete-requests"
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


def _wait_active(ddb, table: str, deadline: float) -> None:
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            i.get("IndexStatus") == "ACTIVE" for i in desc.get("GlobalSecondaryIndexes", [])
        ):
            return
        time.sleep(2)
    raise AssertionError(f"table {table} did not reach ACTIVE before the deadline")


def _item_of_size(pk_value: str, filler_attr: str, total_bytes: int) -> dict:
    """A one-pk, one-filler-attribute item whose aggregate encoded size is exactly total_bytes."""
    overhead = len("pk") + len(pk_value) + len(filler_attr)
    filler_len = total_bytes - overhead
    assert filler_len > 0, f"{total_bytes} bytes is too small for this item shape"
    return {"pk": {"S": pk_value}, filler_attr: {"S": "x" * filler_len}}


def _breakdown(cc):
    """(table_units, gsi1_units) of an INDEXES ConsumedCapacity entry, 0 where absent."""
    table_units = cc.get("Table", {}).get("CapacityUnits", 0)
    gsi_units = cc.get("GlobalSecondaryIndexes", {}).get("gsi1", {}).get("CapacityUnits", 0)
    return table_units, gsi_units


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single BatchWriteItem spanning two tables returns one ConsumedCapacity entry per table
    under ReturnConsumedCapacity=INDEXES, each entry summing its PutRequest and DeleteRequest
    arms, with a DeleteRequest billed by the size of the item it removes.
    """
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 60.0)

    table_a = ctx.unique_name("sim2real-behav-ddbbw-a-")
    ddb.create_table(
        TableName=table_a,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gpk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "gsi1",
            "KeySchema": [{"AttributeName": "gpk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table_a), "ResourceNotFoundException"))

    table_b = ctx.unique_name("sim2real-behav-ddbbw-b-")
    ddb.create_table(
        TableName=table_b,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table_b), "ResourceNotFoundException"))

    _wait_active(ddb, table_a, deadline)
    _wait_active(ddb, table_b, deadline)

    # Pre-seed the items each table's DeleteRequest will remove.
    del_key_a = {"pk": {"S": "a-del"}, "sk": {"S": "1"}}
    ddb.put_item(TableName=table_a, Item={**del_key_a, "gpk": {"S": "g-del"}})
    del_item_b = _item_of_size("b-del", "f", 2500)
    ddb.put_item(TableName=table_b, Item=del_item_b)

    put_item_a = {"pk": {"S": "a-put"}, "sk": {"S": "1"}, "gpk": {"S": "g-put"}}
    put_item_b = _item_of_size("b-put", "f", 1500)

    resp = ddb.batch_write_item(
        RequestItems={
            table_a: [
                {"PutRequest": {"Item": put_item_a}},
                {"DeleteRequest": {"Key": del_key_a}},
            ],
            table_b: [
                {"PutRequest": {"Item": put_item_b}},
                {"DeleteRequest": {"Key": {"pk": del_item_b["pk"]}}},
            ],
        },
        ReturnConsumedCapacity="INDEXES",
    )
    assert resp.get("UnprocessedItems", {}) == {}, (
        f"the four-request batch must be accepted whole, got UnprocessedItems="
        f"{resp.get('UnprocessedItems')!r}"
    )

    entries = resp["ConsumedCapacity"]
    assert isinstance(entries, list) and len(entries) == 2, (
        f"a BatchWriteItem spanning two tables must report one ConsumedCapacity entry per "
        f"table, got {entries!r}"
    )
    by_table = {e["TableName"]: e for e in entries}
    assert set(by_table) == {table_a, table_b}, (
        f"the two entries must name {table_a!r} and {table_b!r}, got {sorted(by_table)!r}"
    )

    entry_a = by_table[table_a]
    table_u, gsi_u = _breakdown(entry_a)
    assert (table_u, gsi_u) == (2.0, 2.0), (
        f"table_a's entry billed table={table_u!r} gsi1={gsi_u!r} for one put and one delete of "
        f"gpk-bearing items, expected (2.0, 2.0): each of the put and the delete bills its own "
        f"table-arm unit and its own gsi1-arm unit"
    )
    assert "LocalSecondaryIndexes" not in entry_a, (
        f"table_a has no LSI, so its entry must carry no LocalSecondaryIndexes member, got {entry_a!r}"
    )
    assert entry_a["CapacityUnits"] == table_u + gsi_u, (
        f"table_a's total {entry_a['CapacityUnits']!r} must equal its table arm {table_u!r} plus "
        f"its gsi1 arm {gsi_u!r}"
    )

    entry_b = by_table[table_b]
    table_u_b, gsi_u_b = _breakdown(entry_b)
    assert gsi_u_b == 0.0 and "GlobalSecondaryIndexes" not in entry_b, (
        f"table_b has no GSI, so its entry must carry no GlobalSecondaryIndexes member, got {entry_b!r}"
    )
    assert table_u_b == 5.0, (
        f"table_b's table arm billed {table_u_b!r} for a 1500-byte put (rounds to 2) and a "
        f"2500-byte delete (rounds to 3), expected 5.0: a DeleteRequest is billed by the size of "
        f"the item it removes, not a flat unit"
    )
    assert entry_b["CapacityUnits"] == table_u_b, (
        f"table_b's total {entry_b['CapacityUnits']!r} must equal its table arm {table_u_b!r} "
        f"when it carries no index"
    )

    got_put_a = ddb.get_item(TableName=table_a, Key={"pk": {"S": "a-put"}, "sk": {"S": "1"}},
                             ConsistentRead=True).get("Item")
    assert got_put_a == put_item_a, f"the put into table_a must have landed, got {got_put_a!r}"
    assert ddb.get_item(TableName=table_a, Key=del_key_a, ConsistentRead=True).get("Item") is None, (
        "the deleted item in table_a must be gone"
    )

    got_put_b = ddb.get_item(TableName=table_b, Key={"pk": {"S": "b-put"}}, ConsistentRead=True).get("Item")
    assert got_put_b == put_item_b, (
        f"the 1500-byte batched put into table_b must round-trip whole, got "
        f"{len(got_put_b.get('f', {}).get('S', '')) if got_put_b else None} bytes back"
    )
    assert ddb.get_item(TableName=table_b, Key={"pk": del_item_b["pk"]}, ConsistentRead=True).get("Item") is None, (
        "the deleted 2500-byte item in table_b must be gone"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
