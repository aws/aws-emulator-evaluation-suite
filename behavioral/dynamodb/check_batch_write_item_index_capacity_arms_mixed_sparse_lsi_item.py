"""batch-write-item-index-capacity-arms-mixed-sparse-lsi-item."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-write-item-index-capacity-arms-mixed-sparse-lsi-item"
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
    """With ReturnConsumedCapacity=INDEXES, one BatchWriteItem writing a fully-indexed item
    and a second item missing only the LSI key reports a single per-table entry whose GSI
    arm sums both items and whose LSI arm reflects only the one that carried it.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbmix-")
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

    full_item = {"pk": {"S": "full"}, "sk": {"S": "1"}, "gpk": {"S": "g-full"}, "lsk": {"N": "1"}}
    sparse_lsi_item = {"pk": {"S": "sparse-lsi"}, "sk": {"S": "1"}, "gpk": {"S": "g-sparse"}}
    resp = ddb.batch_write_item(
        RequestItems={table: [
            {"PutRequest": {"Item": full_item}},
            {"PutRequest": {"Item": sparse_lsi_item}},
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
    assert (table_u, gsi_u, lsi_u) == (2.0, 2.0, 1.0), (
        f"one item carrying every index key and one carrying only the GSI key billed "
        f"table={table_u!r} gsi1={gsi_u!r} lsi1={lsi_u!r}, expected (2.0, 2.0, 1.0)"
    )
    assert entry["CapacityUnits"] == table_u + gsi_u + lsi_u, (
        f"the per-table total {entry['CapacityUnits']!r} must equal the sum of its arms "
        f"{table_u!r} + {gsi_u!r} + {lsi_u!r}"
    )

    got_full = ddb.get_item(TableName=table, Key={"pk": {"S": "full"}, "sk": {"S": "1"}},
                            ConsistentRead=True)["Item"]
    assert got_full == full_item, f"the fully-indexed item must round-trip exactly, got {got_full!r}"
    got_sparse = ddb.get_item(TableName=table, Key={"pk": {"S": "sparse-lsi"}, "sk": {"S": "1"}},
                              ConsistentRead=True)["Item"]
    assert got_sparse == sparse_lsi_item, (
        f"the LSI-sparse item must round-trip with no lsk attribute, got {got_sparse!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
