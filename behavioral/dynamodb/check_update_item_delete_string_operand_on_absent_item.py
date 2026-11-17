"""update-item-delete-string-operand-on-absent-item."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-delete-string-operand-on-absent-item"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]

_DELETE_STRING = (
    "ValidationException",
    "1 validation error detected: Invalid UpdateExpression: Incorrect operand type for "
    "operator or function; operator: DELETE, operand type: STRING, typeSet: ALLOWED_FOR_ADD_OPERAND",
)


def expect_error(fn, code: str, message: str) -> None:
    """Assert `fn()` raises a ClientError with exactly `(code, message)`; raises on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err["Code"], err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem's DELETE action with a String operand is refused for its operand type on an
    item that was never put, and the refused call creates no item; a Set operand on the same
    absent item is accepted as a no-op and likewise creates nothing.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "ghost"}}

    expect_error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE tags :v",
        ExpressionAttributeValues={":v": {"S": "z"}},
    ), *_DELETE_STRING)
    after = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert after is None, f"the rejected DELETE must not create the item, got {after!r}"

    # Positive control: a Set operand against the same absent item is a documented no-op.
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE tags :v",
        ExpressionAttributeValues={":v": {"SS": ["z"]}},
    )
    still_absent = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert still_absent is None, (
        f"the accepted no-op DELETE must not create the item either, got {still_absent!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
