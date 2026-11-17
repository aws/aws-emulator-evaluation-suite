"""update-item-subtraction-literal-operand-type-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-subtraction-literal-operand-type-mismatch-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_ERR_VALIDATION = "ValidationException"
_MSG_OPERAND_TYPE = (
    "1 validation error detected: Invalid UpdateExpression: Incorrect operand type for operator "
    "or function; operator or function: -, operand type: S"
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; the resource's own not-found
    code means it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A subtraction (``x - y``) whose literal operand is a String, not a Number, is rejected
    with ValidationException naming the ``-`` operator and the operand's own type, regardless of
    which side of the subtraction carries the mismatched value, and leaves the item unchanged.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-subtype-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "p"}}
    original = {**key, "num": {"N": "5"}}
    ddb.put_item(TableName=table, Item=original)

    # The String operand on the left of "-".
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET num = :a - :b",
        ExpressionAttributeValues={":a": {"S": "x"}, ":b": {"N": "1"}},
    ))
    assert code == _ERR_VALIDATION, (
        f"SET num = :a - :b with :a a String answered {code!r} ({message!r}), expected "
        f"{_ERR_VALIDATION!r}"
    )
    assert message == _MSG_OPERAND_TYPE, (
        f"SET num = :a - :b with :a a String message is {message!r}, expected {_MSG_OPERAND_TYPE!r}"
    )

    # The String operand on the right of "-".
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET num = :a - :b",
        ExpressionAttributeValues={":a": {"N": "1"}, ":b": {"S": "x"}},
    ))
    assert code == _ERR_VALIDATION, (
        f"SET num = :a - :b with :b a String answered {code!r} ({message!r}), expected "
        f"{_ERR_VALIDATION!r}"
    )
    assert message == _MSG_OPERAND_TYPE, (
        f"SET num = :a - :b with :b a String message is {message!r}, expected {_MSG_OPERAND_TYPE!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, (
        f"after two refused subtractions the item is {unchanged!r}, expected it unchanged from "
        f"{original!r}"
    )

    # Positive control: subtraction with both operands numeric applies normally.
    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET num = :a - :b",
        ExpressionAttributeValues={":a": {"N": "10"}, ":b": {"N": "3"}}, ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"num": {"N": "7"}}, (
        f"SET num = :a - :b with two numeric operands returned {resp['Attributes']!r}, expected num=7"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
