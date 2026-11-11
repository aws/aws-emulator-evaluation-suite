"""update-item-updated-new-includes-unchanged-set-value-and-upsert."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-updated-new-includes-unchanged-set-value-and-upsert"
GROUP = "expressions"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _get(ddb, table, key):
    return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem ReturnValues=UPDATED_NEW lists every SET attribute, including one re-assigned
    its own current value, and an upserting UpdateItem's UPDATED_NEW carries the new attributes.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-updnew-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    key = {"pk": {"S": "existing"}}
    ddb.put_item(TableName=table, Item={**key, "dat": {"S": "kept"}, "cnt": {"N": "1"}, "untouched": {"S": "stay"}})

    resp = ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET #d = :dat, #c = :cnt",
        ExpressionAttributeNames={"#d": "dat", "#c": "cnt"},
        ExpressionAttributeValues={":dat": {"S": "kept"}, ":cnt": {"N": "2"}},
        ReturnValues="UPDATED_NEW",
    )
    attrs = resp["Attributes"]
    assert attrs == {"dat": {"S": "kept"}, "cnt": {"N": "2"}}, (
        f"UPDATED_NEW must list every SET attribute, the unchanged one included, got {attrs!r}"
    )
    assert "untouched" not in attrs, f"UPDATED_NEW must not echo an attribute SET did not name, got {sorted(attrs)!r}"

    stored = _get(ddb, table, key)
    assert stored == {**key, "dat": {"S": "kept"}, "cnt": {"N": "2"}, "untouched": {"S": "stay"}}, (
        f"independent GetItem after the update must show the stored item, got {stored!r}"
    )

    upsert_key = {"pk": {"S": "brand-new"}}
    assert _get(ddb, table, upsert_key) is None, "the upsert target already holds an item before the update"
    resp = ddb.update_item(
        TableName=table, Key=upsert_key,
        UpdateExpression="SET #cr = :c, #ct = :n",
        ExpressionAttributeNames={"#cr": "created", "#ct": "count"},
        ExpressionAttributeValues={":c": {"S": "first"}, ":n": {"N": "0"}},
        ReturnValues="UPDATED_NEW",
    )
    attrs = resp["Attributes"]
    assert attrs == {"created": {"S": "first"}, "count": {"N": "0"}}, (
        f"an upserting UpdateItem's UPDATED_NEW must carry the new attributes, got {attrs!r}"
    )
    assert "pk" not in attrs, f"UPDATED_NEW must not echo the key on an upsert, got {sorted(attrs)!r}"

    created = _get(ddb, table, upsert_key)
    assert created == {**upsert_key, "created": {"S": "first"}, "count": {"N": "0"}}, (
        f"independent GetItem after the upsert must show the created item, got {created!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
