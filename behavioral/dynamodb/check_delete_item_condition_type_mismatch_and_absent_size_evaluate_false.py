"""delete-item-condition-type-mismatch-and-absent-size-evaluate-false."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-condition-type-mismatch-and-absent-size-evaluate-false"
GROUP = "conditions"
SERVICES = ["dynamodb"]
_CCFE = ("ConditionalCheckFailedException", "The conditional request failed")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes are swallowed."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code: str, message: str) -> None:
    """Assert fn() raises exactly (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteItem with a ConditionExpression comparing an N attribute to an S value, or taking
    size() of an attribute absent from the item, evaluates false: ConditionalCheckFailedException,
    never a type coercion or an error about the missing attribute.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-dic-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- Bullet 1: an N attribute compared to an S value is false, not coerced, on DeleteItem. ---
    mismatch_key = {"pk": {"S": "di-type-mismatch"}}
    ddb.put_item(TableName=table, Item={**mismatch_key, "n": {"N": "5"}})

    expect_error(
        lambda: ddb.delete_item(
            TableName=table,
            Key=mismatch_key,
            ConditionExpression="n = :sval",
            ExpressionAttributeValues={":sval": {"S": "5"}},
        ),
        *_CCFE,
    )
    still_there = ddb.get_item(TableName=table, Key=mismatch_key, ConsistentRead=True).get("Item")
    assert still_there == {**mismatch_key, "n": {"N": "5"}}, (
        f"a rejected delete must not remove the item, got {still_there!r}"
    )

    # Positive control: the same attribute compared to a same-typed N value satisfies the delete.
    ddb.delete_item(
        TableName=table,
        Key=mismatch_key,
        ConditionExpression="n = :nval",
        ExpressionAttributeValues={":nval": {"N": "5"}},
    )
    gone = ddb.get_item(TableName=table, Key=mismatch_key, ConsistentRead=True).get("Item")
    assert gone is None, f"expected item absent after the type-matched delete, got {gone!r}"

    # --- Bullet 2: size() of an attribute absent from the item is false on DeleteItem. ---
    absent_key = {"pk": {"S": "di-size-absent"}}
    ddb.put_item(TableName=table, Item={**absent_key, "other": {"S": "x"}})

    expect_error(
        lambda: ddb.delete_item(
            TableName=table,
            Key=absent_key,
            ConditionExpression="size(missing_attr) > :zero",
            ExpressionAttributeValues={":zero": {"N": "0"}},
        ),
        *_CCFE,
    )
    still_there2 = ddb.get_item(TableName=table, Key=absent_key, ConsistentRead=True).get("Item")
    assert still_there2 == {**absent_key, "other": {"S": "x"}}, (
        f"a rejected delete must not remove the item, got {still_there2!r}"
    )

    # Positive control: a sibling item that actually carries the attribute satisfies size() > 0.
    present_key = {"pk": {"S": "di-size-present"}}
    ddb.put_item(TableName=table, Item={**present_key, "missing_attr": {"S": "xyz"}})
    ddb.delete_item(
        TableName=table,
        Key=present_key,
        ConditionExpression="size(missing_attr) > :zero",
        ExpressionAttributeValues={":zero": {"N": "0"}},
    )
    gone2 = ddb.get_item(TableName=table, Key=present_key, ConsistentRead=True).get("Item")
    assert gone2 is None, f"expected item absent after the satisfied-condition delete, got {gone2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
