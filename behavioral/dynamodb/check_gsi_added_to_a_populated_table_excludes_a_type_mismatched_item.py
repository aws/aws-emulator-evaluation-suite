"""gsi-added-to-a-populated-table-excludes-a-type-mismatched-item."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-added-to-a-populated-table-excludes-a-type-mismatched-item"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_BACKFILL_BUDGET_S = 1200
_POLL_INTERVAL_S = 2
# By the time cleanup runs, run() has already confirmed the index is ACTIVE and not backfilling,
# so this only guards against a race with the describe just read; keep it well under the suite's
# cleanup budget.
_CLEANUP_WAIT_S = 60


def _wait_table_active(ddb, table_name):
    ddb.get_waiter("table_exists").wait(
        TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250}
    )


def _wait_gsi_active(ddb, table_name, index_name):
    """Poll until the index reaches ACTIVE with backfilling cleared; never a transitional read."""
    deadline = time.monotonic() + _BACKFILL_BUDGET_S
    status, backfilling = None, None
    while time.monotonic() < deadline:
        described = ddb.describe_table(TableName=table_name)["Table"]
        index = next(
            (i for i in described.get("GlobalSecondaryIndexes", []) if i["IndexName"] == index_name),
            None,
        )
        if index is not None:
            status = index["IndexStatus"]
            backfilling = index.get("Backfilling")
            if status == "ACTIVE" and backfilling in (None, False):
                return
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"{index_name} did not reach ACTIVE within {_BACKFILL_BUDGET_S}s: "
        f"status {status!r}, Backfilling {backfilling!r}"
    )


def _safe_delete_table(ddb, table_name):
    """Delete once no index is still building; DeleteTable refuses it before then."""
    deadline = time.monotonic() + _CLEANUP_WAIT_S
    while True:
        described = ddb.describe_table(TableName=table_name)["Table"]
        busy = [i for i in described.get("GlobalSecondaryIndexes") or [] if i.get("IndexStatus") != "ACTIVE"]
        if described["TableStatus"] == "ACTIVE" and not busy:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"table {table_name} indexes never settled for cleanup")
        time.sleep(_POLL_INTERVAL_S)
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI added by UpdateTable to a populated table skips a pre-existing item whose index-key
    attribute has the wrong type during backfill: once ACTIVE, a Query and a Scan of the index
    return every correctly-typed item and omit that one.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-gsi-backfill-typemismatch-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table))
    _wait_table_active(ddb, table)

    valid_pks = [f"valid-{i}" for i in range(3)]
    for pk in valid_pks:
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "gsi1pk": {"S": "group-A"}})
    # The violating item carries the index key with the WRONG type (N, not S): a real write the
    # table itself accepts because the type only becomes an index-key violation once the index
    # exists.
    ddb.put_item(TableName=table, Item={"pk": {"S": "violator"}, "gsi1pk": {"N": "42"}})

    # The index does not exist yet, so everything the query below finds was backfilled.
    ddb.update_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "gsi1pk", "AttributeType": "S"}],
        GlobalSecondaryIndexUpdates=[
            {
                "Create": {
                    "IndexName": "gsi1",
                    "KeySchema": [{"AttributeName": "gsi1pk", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                }
            }
        ],
    )
    _wait_gsi_active(ddb, table, "gsi1")

    query = ddb.query(
        TableName=table,
        IndexName="gsi1",
        KeyConditionExpression="gsi1pk = :g",
        ExpressionAttributeValues={":g": {"S": "group-A"}},
    )
    query_pks = {item["pk"]["S"] for item in query["Items"]}
    assert query_pks == set(valid_pks), (
        f"gsi1 query under gsi1pk=group-A returned {query_pks!r}, expected exactly {set(valid_pks)!r}"
    )

    # The Scan is the real proof: it enumerates the index's own contents, so an emulator that
    # materializes the violator into the index under some other key value cannot hide behind a
    # query that simply never asked for that value.
    scan = ddb.scan(TableName=table, IndexName="gsi1")
    scan_pks = {item["pk"]["S"] for item in scan["Items"]}
    assert scan_pks == set(valid_pks), (
        f"gsi1 scan returned {scan_pks!r}, expected exactly the correctly-typed items {set(valid_pks)!r}"
    )

    # The violator is still a live item on the base table -- untouched, just unindexed.
    base = ddb.get_item(TableName=table, Key={"pk": {"S": "violator"}}, ConsistentRead=True)
    assert "Item" in base, "the type-mismatched item must still exist on the base table"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
