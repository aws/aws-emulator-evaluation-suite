"""update-item-gsi-key-move-recharges-an-all-projected-lsi."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-gsi-key-move-recharges-an-all-projected-lsi"
GROUP = "capacity"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises on anything but not_found."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_active(ddb, table: str, deadline: float) -> None:
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            i.get("IndexStatus") == "ACTIVE" for i in desc.get("GlobalSecondaryIndexes", [])
        ):
            return
        time.sleep(2)
    raise AssertionError(f"table {table} did not reach ACTIVE with its GSI before the deadline: {desc!r}")


def _breakdown(resp):
    """(table_units, gsi1_units, lsi1_units) of an INDEXES ConsumedCapacity, 0 where absent."""
    cc = resp.get("ConsumedCapacity", {})
    table_units = cc.get("Table", {}).get("CapacityUnits", 0)
    gsi_units = cc.get("GlobalSecondaryIndexes", {}).get("gsi1", {}).get("CapacityUnits", 0)
    lsi_units = cc.get("LocalSecondaryIndexes", {}).get("lsi1", {}).get("CapacityUnits", 0)
    return table_units, gsi_units, lsi_units


def _poll(fn, pred, deadline: float):
    result = fn()
    while not pred(result) and time.monotonic() < deadline:
        time.sleep(2)
        result = fn()
    return result


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem moving a GSI's partition-key attribute bills the GSI 2 (delete plus put) and,
    when the same attribute is projected ALL into an unrelated LSI whose own key is untouched,
    also bills that LSI 1 for re-storing its entry with the new value: table 1 + gsi 2 + lsi 1 = 4.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbgla-")
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
            "Projection": {"ProjectionType": "KEYS_ONLY"},
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

    key = {"pk": {"S": "a"}, "sk": {"S": "1"}}
    ddb.put_item(TableName=table, Item={
        **key, "gpk": {"S": "g-old"}, "lsk": {"N": "7"},
    })

    present = _poll(
        lambda: ddb.query(TableName=table, IndexName="gsi1", KeyConditionExpression="gpk = :v",
                          ExpressionAttributeValues={":v": {"S": "g-old"}}),
        lambda r: r["Count"] == 1, deadline,
    )
    assert present["Count"] == 1, f"item never appeared under gpk=g-old before the update: {present!r}"

    before_lsi = ddb.query(TableName=table, IndexName="lsi1", ConsistentRead=True,
                           KeyConditionExpression="pk = :p AND lsk = :v",
                           ExpressionAttributeValues={":p": {"S": "a"}, ":v": {"N": "7"}})
    assert before_lsi["Items"] == [{**key, "gpk": {"S": "g-old"}, "lsk": {"N": "7"}}], (
        f"the all-projected LSI entry before the update was {before_lsi['Items']!r}"
    )

    resp = ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET gpk = :new", ExpressionAttributeValues={":new": {"S": "g-new"}},
        ReturnConsumedCapacity="INDEXES",
    )
    table_u, gsi_u, lsi_u = _breakdown(resp)
    assert (table_u, gsi_u, lsi_u) == (1.0, 2.0, 1.0), (
        f"moving the GSI key while an unrelated ALL-projected LSI key stayed put billed "
        f"table={table_u!r} gsi1={gsi_u!r} lsi1={lsi_u!r}, expected (1.0, 2.0, 1.0)"
    )
    cc = resp["ConsumedCapacity"]
    assert cc["CapacityUnits"] == 4.0, f"the aggregate CapacityUnits was {cc['CapacityUnits']!r}, expected 4.0"

    moved = _poll(
        lambda: (ddb.query(TableName=table, IndexName="gsi1", KeyConditionExpression="gpk = :v",
                           ExpressionAttributeValues={":v": {"S": "g-new"}})["Items"],
                 ddb.query(TableName=table, IndexName="gsi1", KeyConditionExpression="gpk = :v",
                           ExpressionAttributeValues={":v": {"S": "g-old"}})["Items"]),
        lambda pair: pair[0] and not pair[1], deadline,
    )
    new_items, old_items = moved
    assert [i["pk"]["S"] for i in new_items] == ["a"], f"item never appeared under gpk=g-new: {new_items!r}"
    assert old_items == [], f"the stale gsi1 entry under gpk=g-old survived the key update: {old_items!r}"

    after_lsi = ddb.query(TableName=table, IndexName="lsi1", ConsistentRead=True,
                          KeyConditionExpression="pk = :p AND lsk = :v",
                          ExpressionAttributeValues={":p": {"S": "a"}, ":v": {"N": "7"}})
    assert after_lsi["Items"] == [{**key, "gpk": {"S": "g-new"}, "lsk": {"N": "7"}}], (
        f"the all-projected LSI entry, whose own key never moved, must still have been re-stored "
        f"with the new gpk value: {after_lsi['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
