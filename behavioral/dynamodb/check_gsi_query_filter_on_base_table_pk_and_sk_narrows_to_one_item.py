"""gsi-query-filter-on-base-table-pk-and-sk-narrows-to-one-item."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "gsi-query-filter-on-base-table-pk-and-sk-narrows-to-one-item"
GROUP = "access_path"
SERVICES = ["dynamodb"]
_GSI = "gsi1"
_GH = "shared"
_VISIBLE_S = 180


def _item(pk: str, sk: str) -> dict:
    return {"pk": {"S": pk}, "sk": {"S": sk}, "gh": {"S": _GH}}


_ALPHA = _item("pk-alpha", "sk-alpha")
_BETA = _item("pk-beta", "sk-beta")
_GAMMA = _item("pk-gamma", "sk-gamma")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI Query's FilterExpression on the base table's partition key, and separately on
    its sort key -- neither a key of the queried index -- each narrows the page to the one
    item carrying that value, while ScannedCount still counts the whole index partition.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbgsi-basekeys-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gh", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": _GSI,
            "KeySchema": [{"AttributeName": "gh", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    deadline = time.monotonic() + _VISIBLE_S
    while True:
        gsis = ddb.describe_table(TableName=table)["Table"].get("GlobalSecondaryIndexes", [])
        if gsis and gsis[0]["IndexStatus"] == "ACTIVE":
            break
        assert time.monotonic() < deadline, f"{_GSI} did not reach ACTIVE, last saw {gsis!r}"
        time.sleep(2)

    for item in (_ALPHA, _BETA, _GAMMA):
        ddb.put_item(TableName=table, Item=item)

    # GSIs are eventually consistent: wait for all three items to be visible on gsi1
    # before trusting a filtered page below to mean anything.
    deadline = time.monotonic() + _VISIBLE_S
    unfiltered = {"Count": 0}
    while True:
        unfiltered = ddb.query(TableName=table, IndexName=_GSI, KeyConditionExpression="gh = :g",
                               ExpressionAttributeValues={":g": {"S": _GH}})
        if unfiltered["Count"] == 3 or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert unfiltered["Count"] == 3, (
        f"expected all three seeded items visible on {_GSI} within {_VISIBLE_S}s, "
        f"got Count={unfiltered['Count']}"
    )

    by_sk = ddb.query(TableName=table, IndexName=_GSI, KeyConditionExpression="gh = :g",
                      FilterExpression="sk = :s",
                      ExpressionAttributeValues={":g": {"S": _GH}, ":s": {"S": "sk-beta"}})
    assert by_sk["Items"] == [_BETA], (
        f"filtering gsi1 on the base table's sort key returned {by_sk['Items']!r}, "
        f"expected only {_BETA!r}"
    )
    assert by_sk["Count"] == 1, f"expected Count 1 for the sort-key filter, got {by_sk['Count']!r}"
    assert by_sk["ScannedCount"] == 3, (
        f"expected ScannedCount 3 (the whole gh partition) for the sort-key filter, "
        f"got {by_sk['ScannedCount']!r}"
    )

    by_pk = ddb.query(TableName=table, IndexName=_GSI, KeyConditionExpression="gh = :g",
                      FilterExpression="pk = :p",
                      ExpressionAttributeValues={":g": {"S": _GH}, ":p": {"S": "pk-gamma"}})
    assert by_pk["Items"] == [_GAMMA], (
        f"filtering gsi1 on the base table's partition key returned {by_pk['Items']!r}, "
        f"expected only {_GAMMA!r}"
    )
    assert by_pk["Count"] == 1, f"expected Count 1 for the partition-key filter, got {by_pk['Count']!r}"
    assert by_pk["ScannedCount"] == 3, (
        f"expected ScannedCount 3 (the whole gh partition) for the partition-key filter, "
        f"got {by_pk['ScannedCount']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
