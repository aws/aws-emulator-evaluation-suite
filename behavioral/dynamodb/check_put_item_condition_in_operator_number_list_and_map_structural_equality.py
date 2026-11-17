"""put-item-condition-in-operator-number-list-and-map-structural-equality."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-condition-in-operator-number-list-and-map-structural-equality"
GROUP = "expressions"
SERVICES = ["dynamodb"]
ERR_CCF = "ConditionalCheckFailedException"
MSG_CCF = "The conditional request failed"


def _wait_table_active(ctx, ddb, table_name):
    """Poll DescribeTable until TableStatus is ACTIVE, bounded by the run's remaining time."""
    left = ctx.time_left()
    budget_s = 90.0 if left is None else max(5.0, min(90.0, left - 10.0))
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table_name)["Table"]
        if last["TableStatus"] == "ACTIVE":
            return last
        time.sleep(1.0)
    raise AssertionError(f"table {table_name} never went ACTIVE in {budget_s}s: {last!r}")


def _error(fn):
    """Call fn(); return (code, message), raising on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutItem ConditionExpression's IN operator matches a Number against a value list, and
    matches a Map against a list of Map operands by structural equality, not key order.
    An unmatched value refuses the write with ConditionalCheckFailedException, item unchanged.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbinop-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_table_active(ctx, ddb, table)

    # A Number IN a value list: the stored score (5) is one of the listed operands, so the
    # condition holds and the write applies (positive control for the refusal below).
    ddb.put_item(TableName=table, Item={"pk": {"S": "num_in"}, "score": {"N": "5"}})
    ddb.put_item(
        TableName=table,
        Item={"pk": {"S": "num_in"}, "score": {"N": "5"}, "touched": {"BOOL": True}},
        ConditionExpression="score IN (:a, :b, :c)",
        ExpressionAttributeValues={":a": {"N": "1"}, ":b": {"N": "5"}, ":c": {"N": "9"}},
    )
    item = ddb.get_item(TableName=table, Key={"pk": {"S": "num_in"}}, ConsistentRead=True)["Item"]
    assert item["touched"] == {"BOOL": True}, (
        f"PutItem ConditionExpression 'score IN (1, 5, 9)' with score=5 must apply, got {item!r}"
    )

    # The same condition against a value list that names neither 5 nor anything else the item
    # holds is refused, and the item is left exactly as the prior successful write left it.
    code, msg = _error(lambda: ddb.put_item(
        TableName=table,
        Item={"pk": {"S": "num_in"}, "score": {"N": "5"}, "touched": {"BOOL": False}},
        ConditionExpression="score IN (:a, :b, :c)",
        ExpressionAttributeValues={":a": {"N": "2"}, ":b": {"N": "6"}, ":c": {"N": "10"}},
    ))
    assert code == ERR_CCF, f"PutItem ConditionExpression IN with no matching Number gave code {code!r}"
    assert msg == MSG_CCF, f"expected the exact message {MSG_CCF!r}, got {msg!r}"
    item = ddb.get_item(TableName=table, Key={"pk": {"S": "num_in"}}, ConsistentRead=True)["Item"]
    assert item["touched"] == {"BOOL": True}, (
        f"a refused PutItem must leave touched exactly as the prior successful write left it, got {item!r}"
    )

    # A Map IN a list of Map operands: the stored Map is structurally equal to one listed
    # operand even though that operand's keys (and its nested Map's keys) are written in a
    # different order, so the condition holds and the write applies (positive control).
    stored_map = {"a": {"N": "1"}, "b": {"M": {"inner1": {"S": "m"}, "inner2": {"BOOL": True}}}}
    permuted_match = {"b": {"M": {"inner2": {"BOOL": True}, "inner1": {"S": "m"}}}, "a": {"N": "1"}}
    unrelated = {"a": {"N": "2"}, "b": {"M": {"inner1": {"S": "z"}, "inner2": {"BOOL": False}}}}
    ddb.put_item(TableName=table, Item={"pk": {"S": "map_in"}, "val": {"M": stored_map}})
    ddb.put_item(
        TableName=table,
        Item={"pk": {"S": "map_in"}, "val": {"M": stored_map}, "touched": {"BOOL": True}},
        ConditionExpression="val IN (:m1, :m2)",
        ExpressionAttributeValues={":m1": {"M": permuted_match}, ":m2": {"M": unrelated}},
    )
    item = ddb.get_item(TableName=table, Key={"pk": {"S": "map_in"}}, ConsistentRead=True)["Item"]
    assert item["touched"] == {"BOOL": True}, (
        f"PutItem ConditionExpression IN with a key-order-permuted matching Map must apply, got {item!r}"
    )

    # Neither listed Map operand is structurally equal to the stored Map: the write is
    # refused with ConditionalCheckFailedException and the item is left exactly as the prior
    # successful write left it.
    mismatched_1 = {"a": {"N": "1"}, "b": {"M": {"inner1": {"S": "z"}, "inner2": {"BOOL": True}}}}
    mismatched_2 = {"a": {"N": "3"}, "b": {"M": {"inner1": {"S": "m"}, "inner2": {"BOOL": False}}}}
    code, msg = _error(lambda: ddb.put_item(
        TableName=table,
        Item={"pk": {"S": "map_in"}, "val": {"M": stored_map}, "touched": {"BOOL": False}},
        ConditionExpression="val IN (:m1, :m2)",
        ExpressionAttributeValues={":m1": {"M": mismatched_1}, ":m2": {"M": mismatched_2}},
    ))
    assert code == ERR_CCF, f"PutItem ConditionExpression IN with no structurally matching Map gave code {code!r}"
    assert msg == MSG_CCF, f"expected the exact message {MSG_CCF!r}, got {msg!r}"
    item = ddb.get_item(TableName=table, Key={"pk": {"S": "map_in"}}, ConsistentRead=True)["Item"]
    assert item["touched"] == {"BOOL": True}, (
        f"a refused PutItem must leave touched exactly as the prior successful write left it, got {item!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
