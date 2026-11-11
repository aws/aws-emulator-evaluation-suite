"""update-item-index-capacity-ladder-follows-key-vs-projected-change."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-item-index-capacity-ladder-follows-key-vs-projected-change"
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


def _breakdown(resp):
    """(table_units, gsi1_units, lsi1_units) of an INDEXES ConsumedCapacity, 0 where absent."""
    cc = resp.get("ConsumedCapacity", {})
    table_units = cc.get("Table", {}).get("CapacityUnits", 0)
    gsi_units = cc.get("GlobalSecondaryIndexes", {}).get("gsi1", {}).get("CapacityUnits", 0)
    lsi_units = cc.get("LocalSecondaryIndexes", {}).get("lsi1", {}).get("CapacityUnits", 0)
    return table_units, gsi_units, lsi_units


def _poll_query(query, pred, deadline: float):
    result = query()
    while not pred(result) and time.monotonic() < deadline:
        time.sleep(2)
        result = query()
    return result


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem's index write capacity, with ReturnConsumedCapacity=INDEXES, charges 2 units for
    an index whose key attribute changed value (a delete of the old entry plus a put of the new
    one) and 1 unit for an index that keeps its key but re-stores a changed projected attribute.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbupl-")
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
            "Projection": {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["proj"]},
        }],
        LocalSecondaryIndexes=[{
            "IndexName": "lsi1",
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "lsk", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["proj"]},
        }],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 900.0) - 60.0)
    _wait_active(ddb, table, deadline)

    # --- arm A: an UpdateItem that changes the GSI partition-key attribute ---
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "a"}, "sk": {"S": "1"}, "gpk": {"S": "g-old"}, "lsk": {"N": "1"}, "proj": {"S": "p0"},
    })
    present = _poll_query(
        lambda: ddb.query(TableName=table, IndexName="gsi1", KeyConditionExpression="gpk = :v",
                          ExpressionAttributeValues={":v": {"S": "g-old"}}),
        lambda r: r["Count"] == 1, deadline,
    )
    assert present["Count"] == 1, f"item never appeared under gpk=g-old before the update: {present!r}"

    resp = ddb.update_item(
        TableName=table, Key={"pk": {"S": "a"}, "sk": {"S": "1"}},
        UpdateExpression="SET gpk = :new", ExpressionAttributeValues={":new": {"S": "g-new"}},
        ReturnConsumedCapacity="INDEXES",
    )
    table_u, gsi_u, lsi_u = _breakdown(resp)
    assert (table_u, gsi_u, lsi_u) == (1.0, 2.0, 0.0), (
        f"changing a GSI partition-key attribute billed table={table_u!r} gsi1={gsi_u!r} "
        f"lsi1={lsi_u!r}, expected (1.0, 2.0, 0.0)"
    )

    moved = _poll_query(
        lambda: (ddb.query(TableName=table, IndexName="gsi1", KeyConditionExpression="gpk = :v",
                           ExpressionAttributeValues={":v": {"S": "g-new"}})["Items"],
                 ddb.query(TableName=table, IndexName="gsi1", KeyConditionExpression="gpk = :v",
                           ExpressionAttributeValues={":v": {"S": "g-old"}})["Items"]),
        lambda pair: pair[0] and not pair[1], deadline,
    )
    new_items, old_items = moved
    assert [i["pk"]["S"] for i in new_items] == ["a"], f"item never appeared under gpk=g-new: {new_items!r}"
    assert old_items == [], f"the stale gsi1 entry under gpk=g-old survived the key update: {old_items!r}"

    # --- arm B: an UpdateItem that changes the LSI sort-key attribute ---
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "b"}, "sk": {"S": "1"}, "gpk": {"S": "g-b"}, "lsk": {"N": "5"}, "proj": {"S": "p0"},
    })
    present = _poll_query(
        lambda: ddb.query(TableName=table, IndexName="lsi1", KeyConditionExpression="pk = :p AND lsk = :v",
                          ExpressionAttributeValues={":p": {"S": "b"}, ":v": {"N": "5"}}),
        lambda r: r["Count"] == 1, deadline,
    )
    assert present["Count"] == 1, f"item never appeared under lsk=5 before the update: {present!r}"

    resp = ddb.update_item(
        TableName=table, Key={"pk": {"S": "b"}, "sk": {"S": "1"}},
        UpdateExpression="SET lsk = :new", ExpressionAttributeValues={":new": {"N": "6"}},
        ReturnConsumedCapacity="INDEXES",
    )
    table_u, gsi_u, lsi_u = _breakdown(resp)
    assert (table_u, gsi_u, lsi_u) == (1.0, 0.0, 2.0), (
        f"changing an LSI sort-key attribute billed table={table_u!r} gsi1={gsi_u!r} "
        f"lsi1={lsi_u!r}, expected (1.0, 0.0, 2.0)"
    )

    moved = _poll_query(
        lambda: (ddb.query(TableName=table, IndexName="lsi1", KeyConditionExpression="pk = :p AND lsk = :v",
                           ExpressionAttributeValues={":p": {"S": "b"}, ":v": {"N": "6"}})["Items"],
                 ddb.query(TableName=table, IndexName="lsi1", KeyConditionExpression="pk = :p AND lsk = :v",
                           ExpressionAttributeValues={":p": {"S": "b"}, ":v": {"N": "5"}})["Items"]),
        lambda pair: pair[0] and not pair[1], deadline,
    )
    new_items, old_items = moved
    assert [i["pk"]["S"] for i in new_items] == ["b"], f"item never appeared under lsk=6: {new_items!r}"
    assert old_items == [], f"the stale lsi1 entry under lsk=5 survived the key update: {old_items!r}"

    # --- arm C: an UpdateItem that changes only a projected, non-key attribute ---
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "c"}, "sk": {"S": "1"}, "gpk": {"S": "g-c"}, "lsk": {"N": "9"}, "proj": {"S": "p0"},
    })
    present = _poll_query(
        lambda: ddb.query(TableName=table, IndexName="gsi1", KeyConditionExpression="gpk = :v",
                          ExpressionAttributeValues={":v": {"S": "g-c"}}),
        lambda r: r["Count"] == 1, deadline,
    )
    assert present["Count"] == 1, f"item never appeared under gpk=g-c before the update: {present!r}"

    resp = ddb.update_item(
        TableName=table, Key={"pk": {"S": "c"}, "sk": {"S": "1"}},
        UpdateExpression="SET proj = :new", ExpressionAttributeValues={":new": {"S": "p1"}},
        ReturnConsumedCapacity="INDEXES",
    )
    table_u, gsi_u, lsi_u = _breakdown(resp)
    assert (table_u, gsi_u, lsi_u) == (1.0, 1.0, 1.0), (
        f"changing only a projected, non-key attribute billed table={table_u!r} gsi1={gsi_u!r} "
        f"lsi1={lsi_u!r}, expected (1.0, 1.0, 1.0)"
    )

    via_gsi = _poll_query(
        lambda: ddb.query(TableName=table, IndexName="gsi1", KeyConditionExpression="gpk = :v",
                          ExpressionAttributeValues={":v": {"S": "g-c"}}),
        lambda r: r["Items"] and r["Items"][0].get("proj", {}).get("S") == "p1", deadline,
    )
    assert via_gsi["Items"][0]["proj"]["S"] == "p1", (
        f"the INCLUDE-projection gsi1 entry did not pick up the updated attribute: {via_gsi['Items']!r}"
    )
    via_lsi = ddb.query(TableName=table, IndexName="lsi1", KeyConditionExpression="pk = :p AND lsk = :v",
                        ExpressionAttributeValues={":p": {"S": "c"}, ":v": {"N": "9"}})
    assert via_lsi["Items"][0]["proj"]["S"] == "p1", (
        f"the INCLUDE-projection lsi1 entry did not pick up the updated attribute: {via_lsi['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
