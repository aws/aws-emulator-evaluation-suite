"""online-gsi-add-echoes-include-projection-with-composite-key."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "online-gsi-add-echoes-include-projection-with-composite-key"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_INCLUDE_GSI = "gsi-include-composite"
_WAIT_S = 1500.0


def _poll(fn, pred, *, timeout_s, interval_s=5.0, description="condition"):
    """Poll `fn` until `pred` holds, never a fixed sleep standing in for the wait."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last: {value!r}")
        time.sleep(interval_s)
        value = fn()
    return value


def _index(table, name):
    for g in table.get("GlobalSecondaryIndexes") or []:
        if g["IndexName"] == name:
            return g
    raise AssertionError(f"{name} missing from DescribeTable: {table.get('GlobalSecondaryIndexes')!r}")


@tags(
    "axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
    "dp:api", "plane:data",
)
def run(ctx) -> None:
    """A GSI added online with UpdateTable is described with its INCLUDE projection's
    NonKeyAttributes and its composite (hash+range) KeySchema exactly as declared, and
    backfills an item that existed before the index did, projecting only the named attribute.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddb-onl-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # An item carrying every attribute the index will divide up, written before the index
    # exists so the add must backfill it rather than needing a fresh write.
    ddb.put_item(TableName=t, Item={
        "pk": {"S": "p"}, "g1": {"S": "a1"}, "g2": {"S": "a2"},
        "extra": {"S": "EX"}, "excluded": {"S": "NO"},
    })

    ddb.update_table(
        TableName=t,
        AttributeDefinitions=[
            {"AttributeName": "g1", "AttributeType": "S"},
            {"AttributeName": "g2", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexUpdates=[{
            "Create": {
                "IndexName": _INCLUDE_GSI,
                "KeySchema": [
                    {"AttributeName": "g1", "KeyType": "HASH"},
                    {"AttributeName": "g2", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["extra"]},
            }
        }],
    )
    settled = _poll(
        lambda: ddb.describe_table(TableName=t)["Table"],
        lambda tbl: _index(tbl, _INCLUDE_GSI)["IndexStatus"] == "ACTIVE",
        timeout_s=_WAIT_S, description=f"{_INCLUDE_GSI} ACTIVE",
    )
    include_gsi = _index(settled, _INCLUDE_GSI)
    assert include_gsi["Projection"] == {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["extra"]}, (
        f"an online-added INCLUDE GSI must be described with its NonKeyAttributes, got "
        f"{include_gsi['Projection']!r}"
    )
    assert include_gsi["KeySchema"] == [
        {"AttributeName": "g1", "KeyType": "HASH"}, {"AttributeName": "g2", "KeyType": "RANGE"},
    ], f"expected the composite hash+range KeySchema as declared, got {include_gsi['KeySchema']!r}"

    include_resp = _poll(
        lambda: ddb.query(
            TableName=t, IndexName=_INCLUDE_GSI, KeyConditionExpression="g1 = :g1 AND g2 = :g2",
            ExpressionAttributeValues={":g1": {"S": "a1"}, ":g2": {"S": "a2"}},
        ),
        lambda r: r["Count"] == 1, timeout_s=120, interval_s=2.0,
        description="item backfilled into " + _INCLUDE_GSI,
    )
    include_item = include_resp["Items"][0]
    assert sorted(include_item) == ["extra", "g1", "g2", "pk"], (
        f"an online INCLUDE GSI must project the table key, its own composite key and only the "
        f"named NonKeyAttributes, got {sorted(include_item)!r}"
    )
    assert include_item["extra"] == {"S": "EX"}, include_item


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
