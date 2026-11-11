"""gsi-added-online-indexes-items-written-while-it-builds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-added-online-indexes-items-written-while-it-builds"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_INDEX = "by-color"


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table and its indexes are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 900.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Items written right after UpdateTable adds a GSI, while it builds, are queryable through it
    once ACTIVE, together with the item that existed before; an item without the key is not indexed.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GSI.OnlineOps.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-gsibuild-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    ddb.put_item(TableName=table, Item={"pk": {"S": "before"}, "color": {"S": "red"}})

    ddb.update_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "color", "AttributeType": "S"}],
        GlobalSecondaryIndexUpdates=[{"Create": {
            "IndexName": _INDEX,
            "KeySchema": [{"AttributeName": "color", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }}],
    )
    for pk in ("during-1", "during-2", "during-3"):
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "color": {"S": "red"}})
    ddb.put_item(TableName=table, Item={"pk": {"S": "during-blue"}, "color": {"S": "blue"}})
    ddb.put_item(TableName=table, Item={"pk": {"S": "during-unkeyed"}, "shade": {"S": "red"}})

    desc = _wait_active(ddb, ctx, table)
    indexes = [(g["IndexName"], g["IndexStatus"]) for g in desc.get("GlobalSecondaryIndexes", [])]
    assert indexes == [(_INDEX, "ACTIVE")], f"after the build the table lists GSIs {indexes!r}"

    def red():
        items = []
        for page in ddb.get_paginator("query").paginate(
            TableName=table, IndexName=_INDEX, KeyConditionExpression="color = :c",
            ExpressionAttributeValues={":c": {"S": "red"}},
        ):
            items.extend(page["Items"])
        return sorted(i["pk"]["S"] for i in items)

    def indexed():
        return sorted(
            i["pk"]["S"]
            for page in ddb.get_paginator("scan").paginate(TableName=table, IndexName=_INDEX)
            for i in page["Items"]
        )

    want = ["before", "during-1", "during-2", "during-3"]
    want_all = ["before", "during-1", "during-2", "during-3", "during-blue"]
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 120.0) - 20.0)
    while True:
        got, held = red(), indexed()
        if (got == want and held == want_all) or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert got == want, f"the built GSI answers color = red with {got!r}"
    assert held == want_all, (
        f"the built GSI holds {held!r}; the item without 'color' must be absent"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
