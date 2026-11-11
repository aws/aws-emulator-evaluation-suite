"""condition-ordering-comparison-non-orderable-literal-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-ordering-comparison-non-orderable-literal-rejected"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_OPERAND_TYPE_MSG = (
    "1 validation error detected: Invalid ConditionExpression: Incorrect operand type for "
    "operator or function; operator or function: {op}, operand type: {type}"
)

_NON_ORDERABLE = {
    "BOOL": {"BOOL": True},
    "NULL": {"NULL": True},
    "SS": {"SS": ["a", "b"]},
    "NS": {"NS": ["1", "2"]},
    "L": {"L": [{"S": "a"}]},
    "M": {"M": {"k": {"S": "a"}}},
}
_ORDERING_OPS = ["<", "<=", ">", ">="]

_BASE = {"pk": {"S": "p1"}, "n": {"N": "5"}, "s": {"S": "x"}, "note": {"S": "orig"}}
_CHANGED = {**_BASE, "note": {"S": "changed"}}


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
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A ConditionExpression ordering comparison or BETWEEN with a BOOL/NULL/set/L/M value is
    ValidationException on PutItem, UpdateItem and DeleteItem, even inside a short-circuited or
    negated branch, and the item is unchanged; an orderable literal is accepted.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-cond-order-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    key = {"pk": {"S": "p1"}}
    ddb.put_item(TableName=table, Item=_BASE)

    def put(condition, values):
        return ddb.put_item(TableName=table, Item=_CHANGED, ConditionExpression=condition,
                            ExpressionAttributeValues=values)

    def assert_refused(label, fn, op, type_code):
        want = _OPERAND_TYPE_MSG.format(op=op, type=type_code)
        code, msg = _error(fn)
        assert (code, msg) == ("ValidationException", want), f"{label} gave {code!r}: {msg!r}"

    for type_code, value in _NON_ORDERABLE.items():
        for op in _ORDERING_OPS:
            assert_refused(f"PutItem 'n {op} :v' with a {type_code} value",
                           lambda op=op, value=value: put(f"n {op} :v", {":v": value}), op, type_code)

    assert_refused("PutItem 'n BETWEEN :a AND :b' with BOOL bounds",
                   lambda: put("n BETWEEN :a AND :b", {":a": {"BOOL": True}, ":b": {"BOOL": False}}),
                   "BETWEEN", "BOOL")
    assert_refused("PutItem ':x > :v' with a BOOL right operand",
                   lambda: put(":x > :v", {":x": {"N": "1"}, ":v": {"BOOL": True}}), ">", "BOOL")
    assert_refused("PutItem ':v > :x' with a BOOL left operand",
                   lambda: put(":v > :x", {":v": {"BOOL": True}, ":x": {"N": "1"}}), ">", "BOOL")
    for condition in ("attribute_not_exists(zzz) OR n > :bool",
                      "attribute_exists(zzz) AND n > :bool",
                      "NOT (n > :bool)",
                      "nope > :bool",
                      "size(s) > :bool"):
        assert_refused(f"PutItem {condition!r} with a BOOL value",
                       lambda condition=condition: put(condition, {":bool": {"BOOL": True}}),
                       ">", "BOOL")

    assert_refused(
        "UpdateItem condition 'n > :v' with a BOOL value",
        lambda: ddb.update_item(TableName=table, Key=key, UpdateExpression="SET note = :c",
                                ConditionExpression="n > :v",
                                ExpressionAttributeValues={":c": {"S": "changed"}, ":v": {"BOOL": True}}),
        ">", "BOOL")
    assert_refused(
        "DeleteItem condition 'n > :v' with a BOOL value",
        lambda: ddb.delete_item(TableName=table, Key=key, ConditionExpression="n > :v",
                                ExpressionAttributeValues={":v": {"BOOL": True}}),
        ">", "BOOL")

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert item == _BASE, f"item after every refused conditional write is {item!r}, expected {_BASE!r}"

    put("n > :zero", {":zero": {"N": "0"}})
    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert item == _CHANGED, f"PutItem under 'n > :zero' (5 > 0) left {item!r}, expected {_CHANGED!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
