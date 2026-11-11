"""delete-item-condition-between-bounds-validated."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-condition-between-bounds-validated"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_REVERSED_MSG = (
    "1 validation error detected: Invalid ConditionExpression: The BETWEEN operator requires upper "
    "bound to be greater than or equal to lower bound; lower bound operand: AttributeValue: {lo}, "
    "upper bound operand: AttributeValue: {hi}"
)
_MIXED_TYPE_MSG = (
    "1 validation error detected: Invalid ConditionExpression: The BETWEEN operator requires same "
    "data type for lower and upper bounds; lower bound operand: AttributeValue: {lo}, "
    "upper bound operand: AttributeValue: {hi}"
)


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
    """A DeleteItem condition BETWEEN with reversed N or S bounds, or bounds of different types, is
    ValidationException and the item stays; ordered and equal bounds that hold delete it.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-between-del-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    num_item = {"pk": {"S": "num"}, "v": {"N": "50"}}
    str_item = {"pk": {"S": "str"}, "v": {"S": "m"}}
    ddb.put_item(TableName=table, Item=num_item)
    ddb.put_item(TableName=table, Item=str_item)

    def delete(item, lo, hi):
        return ddb.delete_item(TableName=table, Key={"pk": item["pk"]},
                               ConditionExpression="v BETWEEN :lo AND :hi",
                               ExpressionAttributeValues={":lo": lo, ":hi": hi})

    cases = [
        ("reversed N bounds", num_item, {"N": "100"}, {"N": "1"},
         _REVERSED_MSG.format(lo="{N:100}", hi="{N:1}")),
        ("reversed S bounds", str_item, {"S": "z"}, {"S": "a"},
         _REVERSED_MSG.format(lo="{S:z}", hi="{S:a}")),
        ("N lower and S upper bound", num_item, {"N": "1"}, {"S": "100"},
         _MIXED_TYPE_MSG.format(lo="{N:1}", hi="{S:100}")),
    ]
    for label, item, lo, hi, want in cases:
        code, msg = _error(lambda item=item, lo=lo, hi=hi: delete(item, lo, hi))
        assert (code, msg) == ("ValidationException", want), (
            f"DeleteItem with BETWEEN {label} gave {code!r}: {msg!r}"
        )
        got = ddb.get_item(TableName=table, Key={"pk": item["pk"]}, ConsistentRead=True).get("Item")
        assert got == item, f"DeleteItem refused for BETWEEN {label} left {got!r}, expected {item!r}"

    delete(num_item, {"N": "50"}, {"N": "50"})
    got = ddb.get_item(TableName=table, Key={"pk": num_item["pk"]}, ConsistentRead=True).get("Item")
    assert got is None, f"DeleteItem under 'v BETWEEN 50 AND 50' (v = 50) left {got!r}"

    delete(str_item, {"S": "a"}, {"S": "z"})
    got = ddb.get_item(TableName=table, Key={"pk": str_item["pk"]}, ConsistentRead=True).get("Item")
    assert got is None, f"DeleteItem under \"v BETWEEN 'a' AND 'z'\" (v = 'm') left {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
