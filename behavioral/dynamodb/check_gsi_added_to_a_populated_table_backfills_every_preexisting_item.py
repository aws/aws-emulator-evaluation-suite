"""gsi-added-to-a-populated-table-backfills-every-preexisting-item."""

from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "gsi-added-to-a-populated-table-backfills-every-preexisting-item"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_KEYS = ["A", "B", "C", "D", "E"]
_PER_KEY = 10
_BACKFILL_BUDGET_S = 600


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI added by UpdateTable to a table already holding 50 items reaches ACTIVE with
    Backfilling cleared, and a query of it returns every pre-existing item under its own index
    partition key.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-backfill-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    written_pks = []
    expected_per_key = {}
    for key in _KEYS:
        expected_per_key[key] = _PER_KEY
        batch = []
        for i in range(_PER_KEY):
            item_pk = f"ITEM#{key}#{i:02d}"
            written_pks.append(item_pk)
            batch.append(
                {"PutRequest": {"Item": {"pk": {"S": item_pk}, "gsi1pk": {"S": key}}}}
            )
        pending = {table: batch}
        deadline = time.time() + 120
        while pending and time.time() < deadline:
            pending = (
                ddb.batch_write_item(RequestItems=pending).get("UnprocessedItems") or {}
            )
            if pending:
                time.sleep(1)
        assert not pending, (
            f"BatchWriteItem never drained UnprocessedItems: {pending!r}"
        )
    assert len(written_pks) == len(_KEYS) * _PER_KEY, (
        f"the fixture wrote {len(written_pks)!r} items, expected {len(_KEYS) * _PER_KEY!r}"
    )

    # The index does not exist yet, so everything it returns below was backfilled.
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

    deadline = time.time() + _BACKFILL_BUDGET_S
    status, backfilling = None, None
    while time.time() < deadline:
        described = ddb.describe_table(TableName=table)["Table"]
        index = next(
            (
                i
                for i in described.get("GlobalSecondaryIndexes", [])
                if i["IndexName"] == "gsi1"
            ),
            None,
        )
        if index is not None:
            status = index["IndexStatus"]
            backfilling = index.get("Backfilling")
            if status == "ACTIVE" and backfilling in (None, False):
                break
        time.sleep(5)
    assert status == "ACTIVE", (
        f"gsi1 did not reach ACTIVE within {_BACKFILL_BUDGET_S!r}s: status {status!r}, "
        f"Backfilling {backfilling!r}"
    )
    assert backfilling in (None, False), (
        f"the index reported ACTIVE while still backfilling: {backfilling!r}"
    )

    returned_pks = []
    per_key = {}
    for key in _KEYS:
        got = []
        start_key: dict = {}
        while True:
            page = ddb.query(
                TableName=table,
                IndexName="gsi1",
                KeyConditionExpression="gsi1pk = :g",
                ExpressionAttributeValues={":g": {"S": key}},
                **start_key,
            )
            got += [i["pk"]["S"] for i in page["Items"]]
            if "LastEvaluatedKey" not in page:
                break
            start_key = {"ExclusiveStartKey": page["LastEvaluatedKey"]}
        per_key[key] = len(got)
        returned_pks += got

    assert len(returned_pks) == len(written_pks), (
        f"the backfill missed pre-existing items: the index returned {len(returned_pks)!r} of "
        f"{len(written_pks)!r}"
    )
    assert per_key == expected_per_key, (
        f"the backfill distributed items across the wrong index partitions: {per_key!r}, expected "
        f"{expected_per_key!r}"
    )
    assert sorted(returned_pks) == sorted(written_pks), (
        f"the index contents do not match the base table: symmetric difference "
        f"{sorted(set(written_pks) ^ set(returned_pks))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
