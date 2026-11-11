"""batch-write-item-and-delete-item-index-capacity-arms-follow-item-estate."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-write-item-and-delete-item-index-capacity-arms-follow-item-estate"
GROUP = "capacity"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises on anything but not_found."""
    from botocore.exceptions import ClientError

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
    raise AssertionError(f"table {table} did not reach ACTIVE with its GSI before the deadline")


def _breakdown(cc):
    """(table_units, gsi1_units, lsi1_units) of an INDEXES ConsumedCapacity, 0 where absent."""
    table_units = cc.get("Table", {}).get("CapacityUnits", 0)
    gsi_units = cc.get("GlobalSecondaryIndexes", {}).get("gsi1", {}).get("CapacityUnits", 0)
    lsi_units = cc.get("LocalSecondaryIndexes", {}).get("lsi1", {}).get("CapacityUnits", 0)
    return table_units, gsi_units, lsi_units


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With ReturnConsumedCapacity=INDEXES: a sparse DeleteItem bills only the table arm,
    BatchWriteItem reports one per-table entry summing its table and index arms, and an
    unchanged PutItem overwrite bills the table arm but no index arm.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbbwdl-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gpk", "AttributeType": "S"},
            {"AttributeName": "lsk", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "gsi1",
            "KeySchema": [{"AttributeName": "gpk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        LocalSecondaryIndexes=[{
            "IndexName": "lsi1",
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "lsk", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 900.0) - 60.0)
    _wait_active(ddb, table, deadline)

    # --- DeleteItem of a sparse item (no GSI or LSI key present): table arm only ---
    ddb.put_item(TableName=table, Item={"pk": {"S": "sparse"}, "sk": {"S": "1"}, "v": {"S": "x"}})
    resp = ddb.delete_item(
        TableName=table, Key={"pk": {"S": "sparse"}, "sk": {"S": "1"}}, ReturnConsumedCapacity="INDEXES",
    )
    cc = resp["ConsumedCapacity"]
    table_u, gsi_u, lsi_u = _breakdown(cc)
    assert (table_u, gsi_u, lsi_u) == (1.0, 0.0, 0.0), (
        f"deleting a sparse item (no index keys) billed table={table_u!r} gsi1={gsi_u!r} "
        f"lsi1={lsi_u!r}, expected (1.0, 0.0, 0.0)"
    )
    assert "GlobalSecondaryIndexes" not in cc and "LocalSecondaryIndexes" not in cc, (
        f"a sparse-item delete must carry no index breakdown members at all, got {cc!r}"
    )
    assert ddb.get_item(TableName=table, Key={"pk": {"S": "sparse"}, "sk": {"S": "1"}},
                        ConsistentRead=True).get("Item") is None, "the deleted sparse item must be gone"

    # --- BatchWriteItem under ReturnConsumedCapacity=INDEXES: one entry per table, summed ---
    resp = ddb.batch_write_item(
        RequestItems={table: [
            {"PutRequest": {"Item": {"pk": {"S": "b1"}, "sk": {"S": "1"},
                                      "gpk": {"S": "g1"}, "lsk": {"N": "1"}}}},
            {"PutRequest": {"Item": {"pk": {"S": "b2"}, "sk": {"S": "1"},
                                      "gpk": {"S": "g2"}, "lsk": {"N": "2"}}}},
        ]},
        ReturnConsumedCapacity="INDEXES",
    )
    entries = resp["ConsumedCapacity"]
    assert isinstance(entries, list) and len(entries) == 1, (
        f"BatchWriteItem against one table must report exactly one entry, got {entries!r}"
    )
    entry = entries[0]
    assert entry["TableName"] == table, f"the entry must name {table!r}, got {entry.get('TableName')!r}"
    table_u, gsi_u, lsi_u = _breakdown(entry)
    assert (table_u, gsi_u, lsi_u) == (2.0, 2.0, 2.0), (
        f"two inserts into one GSI and one LSI billed table={table_u!r} gsi1={gsi_u!r} "
        f"lsi1={lsi_u!r}, expected (2.0, 2.0, 2.0)"
    )
    assert entry["CapacityUnits"] == table_u + gsi_u + lsi_u, (
        f"the per-table total {entry['CapacityUnits']!r} must equal the sum of its arms "
        f"{table_u!r} + {gsi_u!r} + {lsi_u!r}"
    )
    for pk, gpk, lsk in (("b1", "g1", "1"), ("b2", "g2", "2")):
        item = ddb.get_item(TableName=table, Key={"pk": {"S": pk}, "sk": {"S": "1"}},
                            ConsistentRead=True).get("Item")
        want = {"pk": {"S": pk}, "sk": {"S": "1"}, "gpk": {"S": gpk}, "lsk": {"N": lsk}}
        assert item == want, f"BatchWriteItem must have written {want!r}, got {item!r}"

    # --- PutItem that rewrites an item with every value identical: no index arm ---
    unchanged_item = {"pk": {"S": "same"}, "sk": {"S": "1"}, "gpk": {"S": "g-same"}, "lsk": {"N": "9"}}
    first = ddb.put_item(TableName=table, Item=unchanged_item, ReturnConsumedCapacity="INDEXES")
    first_table_u, first_gsi_u, first_lsi_u = _breakdown(first["ConsumedCapacity"])
    assert (first_table_u, first_gsi_u, first_lsi_u) == (1.0, 1.0, 1.0), (
        f"the first insert billed table={first_table_u!r} gsi1={first_gsi_u!r} "
        f"lsi1={first_lsi_u!r}, expected (1.0, 1.0, 1.0)"
    )

    second = ddb.put_item(TableName=table, Item=dict(unchanged_item), ReturnConsumedCapacity="INDEXES")
    cc2 = second["ConsumedCapacity"]
    table_u, gsi_u, lsi_u = _breakdown(cc2)
    assert table_u == 1.0, f"an identical overwrite must still bill the table arm, got {table_u!r}"
    assert (gsi_u, lsi_u) == (0.0, 0.0), (
        f"an identical overwrite changes no index entry and must bill no index arm, got "
        f"gsi1={gsi_u!r} lsi1={lsi_u!r}"
    )
    assert "GlobalSecondaryIndexes" not in cc2 and "LocalSecondaryIndexes" not in cc2, (
        f"an identical overwrite must carry no index breakdown members at all, got {cc2!r}"
    )
    still_there = ddb.get_item(TableName=table, Key={"pk": {"S": "same"}, "sk": {"S": "1"}},
                               ConsistentRead=True)["Item"]
    assert still_there == unchanged_item, (
        f"the identical overwrite must leave the item exactly as written: {still_there!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
