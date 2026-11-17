"""delete-item-three-term-condition-expression-and-gates-the-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-three-term-condition-expression-and-gates-the-delete"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_CCFE = ("ConditionalCheckFailedException", "The conditional request failed")

_COND = "attribute_exists(pk) AND ver = :v AND #st = :s"


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


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A three-term ConditionExpression AND on DeleteItem needs every term true: one false
    term raises ConditionalCheckFailedException and leaves the item untouched; all three true
    deletes it.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-del3and-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def get(pk: str):
        return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")

    # --- one term false (status mismatch): attribute_exists(pk) true, ver = :v true, #st = :s false ---
    key_fail = {"pk": {"S": "fail"}}
    base_fail = {**key_fail, "ver": {"N": "1"}, "status": {"S": "B"}}
    ddb.put_item(TableName=table, Item=base_fail)

    expect_error(
        lambda: ddb.delete_item(
            TableName=table, Key=key_fail,
            ConditionExpression=_COND,
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":v": {"N": "1"}, ":s": {"S": "A"}},
        ),
        *_CCFE,
    )
    still_there = get("fail")
    assert still_there == base_fail, (
        f"DeleteItem under a three-term AND with one false term changed the item to {still_there!r}"
    )

    # --- positive control: all three terms true ---
    key_pass = {"pk": {"S": "pass"}}
    base_pass = {**key_pass, "ver": {"N": "1"}, "status": {"S": "A"}}
    ddb.put_item(TableName=table, Item=base_pass)

    ddb.delete_item(
        TableName=table, Key=key_pass,
        ConditionExpression=_COND,
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":v": {"N": "1"}, ":s": {"S": "A"}},
    )
    gone = get("pass")
    assert gone is None, f"DeleteItem under a three-term AND with all terms true left {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
