"""condition-contains-set-element-gates-update-and-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-contains-set-element-gates-update-and-delete"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_COND_FAILED = ("ConditionalCheckFailedException", "The conditional request failed")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""
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


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success fails too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """contains(set, element) in a ConditionExpression tests string-set membership: the write
    applies when the element is present and is refused, item unchanged, when it is absent.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-contains-set-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    names = {"#r": "roles"}
    roles = {"SS": ["admin", "viewer"]}

    # --- UpdateItem ---
    update_key = {"pk": {"S": "update-target"}}
    ddb.put_item(TableName=table, Item={**update_key, "roles": roles})

    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=update_key, UpdateExpression="SET #st = :s",
            ConditionExpression="contains(#r, :v)",
            ExpressionAttributeNames={**names, "#st": "status"},
            ExpressionAttributeValues={":v": {"S": "suspended"}, ":s": {"S": "promoted"}},
        ),
        *_COND_FAILED,
    )
    item = ddb.get_item(TableName=table, Key=update_key, ConsistentRead=True)["Item"]
    assert item == {**update_key, "roles": roles}, (
        f"UpdateItem under a failing contains() condition left {item!r}"
    )

    ddb.update_item(
        TableName=table, Key=update_key, UpdateExpression="SET #st = :s",
        ConditionExpression="contains(#r, :v)",
        ExpressionAttributeNames={**names, "#st": "status"},
        ExpressionAttributeValues={":v": {"S": "admin"}, ":s": {"S": "promoted"}},
    )
    item = ddb.get_item(TableName=table, Key=update_key, ConsistentRead=True)["Item"]
    assert item == {**update_key, "roles": roles, "status": {"S": "promoted"}}, (
        f"UpdateItem under a holding contains() condition left {item!r}"
    )

    # --- DeleteItem ---
    delete_key = {"pk": {"S": "delete-target"}}
    ddb.put_item(TableName=table, Item={**delete_key, "roles": roles})

    expect_error(
        lambda: ddb.delete_item(
            TableName=table, Key=delete_key, ConditionExpression="contains(#r, :v)",
            ExpressionAttributeNames=names, ExpressionAttributeValues={":v": {"S": "suspended"}},
        ),
        *_COND_FAILED,
    )
    item = ddb.get_item(TableName=table, Key=delete_key, ConsistentRead=True)["Item"]
    assert item == {**delete_key, "roles": roles}, (
        f"DeleteItem under a failing contains() condition left {item!r}"
    )

    ddb.delete_item(
        TableName=table, Key=delete_key, ConditionExpression="contains(#r, :v)",
        ExpressionAttributeNames=names, ExpressionAttributeValues={":v": {"S": "admin"}},
    )
    item = ddb.get_item(TableName=table, Key=delete_key, ConsistentRead=True).get("Item")
    assert item is None, f"DeleteItem under a holding contains() condition left {item!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
