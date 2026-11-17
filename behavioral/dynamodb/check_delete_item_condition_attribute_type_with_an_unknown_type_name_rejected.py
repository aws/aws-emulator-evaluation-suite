"""delete-item-condition-attribute-type-with-an-unknown-type-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-condition-attribute-type-with-an-unknown-type-name-rejected"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_KEY = {"pk": {"S": "item-1"}}
_ITEM = {**_KEY, "status": {"S": "active"}}


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


def _error(fn) -> tuple:
    """The (code, message) of the ClientError ``fn()`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteItem's ConditionExpression attribute_type(#a, :t) with :t naming no DynamoDB type
    is refused ValidationException, not ConditionalCheckFailedException, and the item stays.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-delunk-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item=_ITEM)

    # Break exactly one thing: the type operand names no DynamoDB type.
    code, message = _error(lambda: ddb.delete_item(
        TableName=table, Key=_KEY, ConditionExpression="attribute_type(#a, :t)",
        ExpressionAttributeNames={"#a": "status"}, ExpressionAttributeValues={":t": {"S": "STRING"}},
    ))
    assert code == "ValidationException", (
        f"the malformed condition was refused with {code!r} ({message!r}), expected "
        "ValidationException, not ConditionalCheckFailedException"
    )
    expected = (
        "1 validation error detected: Invalid ConditionExpression: Invalid attribute type name "
        "found; type: STRING, valid types: {S,SS,N,NS,B,BS,BOOL,NULL,L,M}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    got = ddb.get_item(TableName=table, Key=_KEY, ConsistentRead=True).get("Item")
    assert got == _ITEM, f"after the rejection the item must be unchanged, got {got!r}"

    # Positive control: the correctly typed condition lets the delete through.
    ddb.delete_item(
        TableName=table, Key=_KEY, ConditionExpression="attribute_type(#a, :t)",
        ExpressionAttributeNames={"#a": "status"}, ExpressionAttributeValues={":t": {"S": "S"}},
    )
    got = ddb.get_item(TableName=table, Key=_KEY, ConsistentRead=True).get("Item")
    assert got is None, f"the correctly typed condition must let the delete apply, got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
