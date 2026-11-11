"""update-item-return-values-omit-attributes-when-no-value-qualifies."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-return-values-omit-attributes-when-no-value-qualifies"
GROUP = "update-expression"
SERVICES = ["dynamodb"]


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
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UPDATED_NEW after REMOVE, UPDATED_OLD after SET of a new attribute, and UPDATED_NEW after
    a legacy AttributeUpdates DELETE omit Attributes entirely, while each update still applies.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-rvomit-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    key = {"pk": {"S": "rv"}}
    ddb.put_item(TableName=table, Item={
        **key,
        "gone": {"S": "present"},
        "m": {"M": {"k": {"S": "v"}}},
        "keep": {"S": "old"},
    })

    resp = ddb.update_item(TableName=table, Key=key, UpdateExpression="REMOVE gone",
                           ReturnValues="UPDATED_NEW")
    assert "Attributes" not in resp, (
        f"REMOVE of a present attribute with UPDATED_NEW returned {resp.get('Attributes')!r}"
    )

    resp = ddb.update_item(TableName=table, Key=key, UpdateExpression="SET fresh = :f",
                           ExpressionAttributeValues={":f": {"S": "new"}},
                           ReturnValues="UPDATED_OLD")
    assert "Attributes" not in resp, (
        f"SET of a brand-new attribute with UPDATED_OLD returned {resp.get('Attributes')!r}"
    )

    resp = ddb.update_item(TableName=table, Key=key,
                           AttributeUpdates={"m": {"Action": "DELETE"}},
                           ReturnValues="UPDATED_NEW")
    assert "Attributes" not in resp, (
        f"AttributeUpdates DELETE of a map with UPDATED_NEW returned {resp.get('Attributes')!r}"
    )

    # Positive control: a value that does qualify is returned.
    resp = ddb.update_item(TableName=table, Key=key, UpdateExpression="SET keep = :k",
                           ExpressionAttributeValues={":k": {"S": "new"}},
                           ReturnValues="UPDATED_NEW")
    assert resp.get("Attributes") == {"keep": {"S": "new"}}, (
        f"SET keep with UPDATED_NEW returned {resp.get('Attributes')!r}, expected keep=new"
    )

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    want = {**key, "fresh": {"S": "new"}, "keep": {"S": "new"}}
    assert item == want, f"after the updates the item is {item!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
