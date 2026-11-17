"""update-item-condition-list-null-bool-equality-and-in-over-map."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-condition-list-null-bool-equality-and-in-over-map"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_CCF = ("ConditionalCheckFailedException", "The conditional request failed")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; the resource's own not-found codes pass."""
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable until TableStatus is ACTIVE, bounded by the run's remaining time."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def expect_error(fn, code: str, message: str) -> None:
    """Call fn(); assert it raised exactly (code, message); raise on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem's ConditionExpression matches a List by whole-value equality, a Map through
    IN, and NULL only against another NULL; a near-miss is ConditionalCheckFailedException and
    leaves the item exactly as the prior successful write left it.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-condeq-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    keys = {
        "list": {"pk": {"S": "list"}},
        "map": {"pk": {"S": "map"}},
        "null": {"pk": {"S": "null"}},
        "bool": {"pk": {"S": "bool"}},
        "str": {"pk": {"S": "str"}},
    }
    ddb.put_item(TableName=table, Item={**keys["list"], "val": {"L": [{"N": "1"}, {"N": "2"}]}})
    ddb.put_item(TableName=table, Item={**keys["map"], "val": {"M": {"x": {"N": "1"}}}})
    ddb.put_item(TableName=table, Item={**keys["null"], "val": {"NULL": True}})
    ddb.put_item(TableName=table, Item={**keys["bool"], "val": {"BOOL": True}})
    ddb.put_item(TableName=table, Item={**keys["str"], "val": {"S": "abc"}})

    def get(name):
        return ddb.get_item(TableName=table, Key=keys[name], ConsistentRead=True)["Item"]

    # A List matches a ConditionExpression equality only as a whole value, element by element.
    ddb.update_item(
        TableName=table, Key=keys["list"], UpdateExpression="SET touched = :t",
        ConditionExpression="val = :v",
        ExpressionAttributeValues={":t": {"BOOL": True}, ":v": {"L": [{"N": "1"}, {"N": "2"}]}},
    )
    item = get("list")
    assert item["touched"] == {"BOOL": True}, (
        f"ConditionExpression 'val = :v' with the exact List value must apply, got {item!r}"
    )
    expect_error(lambda: ddb.update_item(
        TableName=table, Key=keys["list"], UpdateExpression="SET touched = :t",
        ConditionExpression="val = :v",
        ExpressionAttributeValues={":t": {"BOOL": False}, ":v": {"L": [{"N": "1"}, {"N": "3"}]}},
    ), *_CCF)
    item = get("list")
    assert item["touched"] == {"BOOL": True}, (
        f"a refused List condition must leave touched exactly as the prior successful write left it, got {item!r}"
    )

    # A Map matches an IN list by comparing each operand to it structurally, not by identity.
    ddb.update_item(
        TableName=table, Key=keys["map"], UpdateExpression="SET touched = :t",
        ConditionExpression="val IN (:v1, :v2)",
        ExpressionAttributeValues={
            ":t": {"BOOL": True},
            ":v1": {"M": {"x": {"N": "9"}}},
            ":v2": {"M": {"x": {"N": "1"}}},
        },
    )
    item = get("map")
    assert item["touched"] == {"BOOL": True}, (
        f"ConditionExpression 'val IN (:v1, :v2)' must apply once a Map operand matches, got {item!r}"
    )
    expect_error(lambda: ddb.update_item(
        TableName=table, Key=keys["map"], UpdateExpression="SET touched = :t",
        ConditionExpression="val IN (:v1, :v3)",
        ExpressionAttributeValues={
            ":t": {"BOOL": False},
            ":v1": {"M": {"x": {"N": "9"}}},
            ":v3": {"M": {"x": {"N": "2"}}},
        },
    ), *_CCF)
    item = get("map")
    assert item["touched"] == {"BOOL": True}, (
        f"a refused Map IN condition must leave touched exactly as the prior successful write left it, got {item!r}"
    )

    # NULL compares equal only to another NULL, never to a differently-typed value.
    ddb.update_item(
        TableName=table, Key=keys["null"], UpdateExpression="SET touched = :t",
        ConditionExpression="val = :v",
        ExpressionAttributeValues={":t": {"BOOL": True}, ":v": {"NULL": True}},
    )
    item = get("null")
    assert item["touched"] == {"BOOL": True}, (
        f"ConditionExpression 'val = :v' with NULL = NULL must apply, got {item!r}"
    )
    expect_error(lambda: ddb.update_item(
        TableName=table, Key=keys["str"], UpdateExpression="SET touched = :t",
        ConditionExpression="val = :v",
        ExpressionAttributeValues={":t": {"BOOL": True}, ":v": {"NULL": True}},
    ), *_CCF)
    item = get("str")
    assert "touched" not in item, (
        f"a refused 'val = :v' with :v NULL against a String value must leave the item untouched, got {item!r}"
    )

    # BOOL equality matches only the same boolean value.
    ddb.update_item(
        TableName=table, Key=keys["bool"], UpdateExpression="SET touched = :t",
        ConditionExpression="val = :v",
        ExpressionAttributeValues={":t": {"BOOL": True}, ":v": {"BOOL": True}},
    )
    item = get("bool")
    assert item["touched"] == {"BOOL": True}, (
        f"ConditionExpression 'val = :v' with the matching BOOL value must apply, got {item!r}"
    )
    expect_error(lambda: ddb.update_item(
        TableName=table, Key=keys["bool"], UpdateExpression="SET touched = :t",
        ConditionExpression="val = :v",
        ExpressionAttributeValues={":t": {"BOOL": False}, ":v": {"BOOL": False}},
    ), *_CCF)
    item = get("bool")
    assert item["touched"] == {"BOOL": True}, (
        f"a refused BOOL condition must leave touched exactly as the prior successful write left it, got {item!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
