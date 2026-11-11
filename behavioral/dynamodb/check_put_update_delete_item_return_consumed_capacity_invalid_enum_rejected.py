"""put-update-delete-item-return-consumed-capacity-invalid-enum-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-update-delete-item-return-consumed-capacity-invalid-enum-rejected"
GROUP = "capacity"
SERVICES = ["dynamodb"]

_VALIDATION = (
    "ValidationException",
    "1 validation error detected: Value 'BOGUS' at 'returnConsumedCapacity' failed to satisfy "
    "constraint: Member must satisfy enum value set: [INDEXES, TOTAL, NONE]",
)
# UpdateItem answers the same constraint without the "1 validation error detected: " prefix.
_VALIDATION_UPDATE = (
    "ValidationException",
    "Value 'BOGUS' at 'returnConsumedCapacity' failed to satisfy constraint: Member must satisfy "
    "enum value set: [INDEXES, TOTAL, NONE]",
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got = _error(fn)
    assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem, UpdateItem and DeleteItem each reject an out-of-enum ReturnConsumedCapacity with a
    ValidationException naming the offending value, and the item is left untouched.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbrccenum-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # PutItem: the invalid call is rejected and no item is created.
    expect_error(
        lambda: ddb.put_item(TableName=table, Item={"pk": {"S": "a"}, "v": {"S": "1"}},
                             ReturnConsumedCapacity="BOGUS"),
        *_VALIDATION,
    )
    assert ddb.get_item(TableName=table, Key={"pk": {"S": "a"}}, ConsistentRead=True).get("Item") is None, (
        "the rejected PutItem must not have created an item"
    )
    ddb.put_item(TableName=table, Item={"pk": {"S": "a"}, "v": {"S": "1"}})
    created = ddb.get_item(TableName=table, Key={"pk": {"S": "a"}}, ConsistentRead=True)["Item"]
    assert created["v"]["S"] == "1", f"the positive-control PutItem did not persist: {created!r}"

    # UpdateItem: the invalid call is rejected and the existing value is left in place.
    expect_error(
        lambda: ddb.update_item(TableName=table, Key={"pk": {"S": "a"}},
                                UpdateExpression="SET v = :v", ExpressionAttributeValues={":v": {"S": "2"}},
                                ReturnConsumedCapacity="BOGUS"),
        *_VALIDATION_UPDATE,
    )
    unchanged = ddb.get_item(TableName=table, Key={"pk": {"S": "a"}}, ConsistentRead=True)["Item"]
    assert unchanged["v"]["S"] == "1", f"the rejected UpdateItem must not have changed the item: {unchanged!r}"
    ddb.update_item(TableName=table, Key={"pk": {"S": "a"}}, UpdateExpression="SET v = :v",
                    ExpressionAttributeValues={":v": {"S": "2"}})
    updated = ddb.get_item(TableName=table, Key={"pk": {"S": "a"}}, ConsistentRead=True)["Item"]
    assert updated["v"]["S"] == "2", f"the positive-control UpdateItem did not persist: {updated!r}"

    # DeleteItem: the invalid call is rejected and the item survives.
    expect_error(
        lambda: ddb.delete_item(TableName=table, Key={"pk": {"S": "a"}}, ReturnConsumedCapacity="BOGUS"),
        *_VALIDATION,
    )
    survives = ddb.get_item(TableName=table, Key={"pk": {"S": "a"}}, ConsistentRead=True).get("Item")
    assert survives is not None and survives["v"]["S"] == "2", (
        f"the rejected DeleteItem must not have deleted the item: {survives!r}"
    )
    ddb.delete_item(TableName=table, Key={"pk": {"S": "a"}})
    assert ddb.get_item(TableName=table, Key={"pk": {"S": "a"}}, ConsistentRead=True).get("Item") is None, (
        "the positive-control DeleteItem must have removed the item"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
