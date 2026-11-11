"""get-item-and-query-return-consumed-capacity-invalid-enum-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-item-and-query-return-consumed-capacity-invalid-enum-rejected"
GROUP = "capacity"
SERVICES = ["dynamodb"]
_VALIDATION = (
    "ValidationException",
    "1 validation error detected: Value 'BOGUS' at 'returnConsumedCapacity' failed to satisfy "
    "constraint: Member must satisfy enum value set: [INDEXES, TOTAL, NONE]",
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
    """An out-of-enum ReturnConsumedCapacity is ValidationException on GetItem and Query alike,
    and a well-formed call with the same key still reads the item correctly.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-rccenum-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={"pk": {"S": "control"}, "data": {"S": "v"}})

    expect_error(
        lambda: ddb.get_item(TableName=table, Key={"pk": {"S": "control"}},
                             ReturnConsumedCapacity="BOGUS"),
        *_VALIDATION,
    )
    control_get = ddb.get_item(TableName=table, Key={"pk": {"S": "control"}},
                               ReturnConsumedCapacity="TOTAL", ConsistentRead=True)
    assert control_get["Item"] == {"pk": {"S": "control"}, "data": {"S": "v"}}, (
        f"the rejected GetItem must leave the item untouched, read back {control_get.get('Item')!r}"
    )
    assert control_get["ConsumedCapacity"]["CapacityUnits"] == 1.0, (
        f"a well-formed, strongly consistent GetItem of this small item must still bill 1.0 RCU, "
        f"got {control_get['ConsumedCapacity']!r}"
    )

    expect_error(
        lambda: ddb.query(TableName=table, KeyConditionExpression="pk = :v",
                          ExpressionAttributeValues={":v": {"S": "control"}},
                          ReturnConsumedCapacity="BOGUS"),
        *_VALIDATION,
    )
    control_query = ddb.query(TableName=table, KeyConditionExpression="pk = :v",
                              ExpressionAttributeValues={":v": {"S": "control"}},
                              ReturnConsumedCapacity="TOTAL", ConsistentRead=True)
    assert control_query["Count"] == 1, (
        f"the rejected Query must leave the item queryable, got Count={control_query['Count']}"
    )
    assert control_query["Items"][0] == {"pk": {"S": "control"}, "data": {"S": "v"}}, (
        f"the rejected Query must leave the item untouched, read back {control_query['Items'][0]!r}"
    )
    assert control_query["ConsumedCapacity"]["CapacityUnits"] == 1.0, (
        f"a well-formed, strongly consistent Query of this small item must still bill 1.0 RCU, "
        f"got {control_query['ConsumedCapacity']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
