"""delete-item-condition-functions-that-hold-apply-the-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-condition-functions-that-hold-apply-the-delete"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_COND_FAILED = ("ConditionalCheckFailedException", "The conditional request failed")


def _unordered_sets(item):
    """``item`` with every set member list sorted: DynamoDB sets carry no member order."""
    if item is None:
        return None
    return {
        name: {t: sorted(v) if t in ("SS", "NS", "BS") else v for t, v in value.items()}
        for name, value in item.items()
    }


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


def _expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success fails too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A DeleteItem ConditionExpression using attribute_type, begins_with or contains is
    evaluated against the stored item: it holds and the delete applies, or it fails and the
    item is left exactly as it was.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-delcond-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    cases = (
        # (pk, attr name, attr value, holding condition expr/values, failing (near-miss) expr/values)
        ("null-type", "v", {"NULL": True},
         "attribute_type(#a, :t)", {":t": {"S": "NULL"}},
         "attribute_type(#a, :t)", {":t": {"S": "S"}}),
        ("n-type", "v", {"N": "42"},
         "attribute_type(#a, :t)", {":t": {"S": "N"}},
         "attribute_type(#a, :t)", {":t": {"S": "S"}}),
        ("s-type", "v", {"S": "hello"},
         "attribute_type(#a, :t)", {":t": {"S": "S"}},
         "attribute_type(#a, :t)", {":t": {"S": "N"}}),
        ("begins-with", "name", {"S": "widget-42"},
         "begins_with(#a, :p)", {":p": {"S": "widget-"}},
         "begins_with(#a, :p)", {":p": {"S": "gadget-"}}),
        ("contains-ns", "tags", {"NS": ["10", "20", "30"]},
         "contains(#a, :n)", {":n": {"N": "20"}},
         "contains(#a, :n)", {":n": {"N": "99"}}),
        ("contains-str", "desc", {"S": "a quick brown fox"},
         "contains(#a, :s)", {":s": {"S": "brown"}},
         "contains(#a, :s)", {":s": {"S": "purple"}}),
    )

    for pk, attr, value, hold_expr, hold_values, fail_expr, fail_values in cases:
        key = {"pk": {"S": pk}}
        item = {**key, attr: value}
        ddb.put_item(TableName=table, Item=item)
        attr_names = {"#a": attr}

        _expect_error(
            lambda fail_expr=fail_expr, fail_values=fail_values, attr_names=attr_names, key=key: ddb.delete_item(
                TableName=table, Key=key, ConditionExpression=fail_expr,
                ExpressionAttributeNames=attr_names, ExpressionAttributeValues=fail_values,
            ),
            *_COND_FAILED,
        )
        got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
        assert _unordered_sets(got) == _unordered_sets(item), (
            f"{pk}: DeleteItem under a failing {fail_expr!r} must leave the item unchanged, got {got!r}"
        )

        ddb.delete_item(
            TableName=table, Key=key, ConditionExpression=hold_expr,
            ExpressionAttributeNames=attr_names, ExpressionAttributeValues=hold_values,
        )
        got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
        assert got is None, f"{pk}: DeleteItem under a holding {hold_expr!r} must delete it, got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
