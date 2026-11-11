"""delete-set-operand-type-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-set-operand-type-mismatch-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]


def _error(fn) -> tuple:
    """(code, message) of the ClientError `fn()` raises; RAISES if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem's DELETE action is refused for a non-set operand, and separately for a set
    operand of a type other than the attribute's; a same-typed DELETE still removes an element.
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
    ddb.put_item(TableName=table, Item={"pk": {"S": "x"}, "tags": {"SS": ["a", "b"]}})

    names = {"#s": "tags"}

    code1, message1 = _error(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": "x"}}, UpdateExpression="DELETE #s :v",
        ExpressionAttributeNames=names, ExpressionAttributeValues={":v": {"N": "5"}},
    ))
    expected1 = (
        "1 validation error detected: Invalid UpdateExpression: Incorrect operand type for "
        "operator or function; operator: DELETE, operand type: NUMBER, typeSet: ALLOWED_FOR_ADD_OPERAND"
    )
    assert (code1, message1) == ("ValidationException", expected1), (
        f"DELETE #s :v with a Number operand raised {(code1, message1)!r}, expected "
        f"{('ValidationException', expected1)!r}"
    )

    code2, message2 = _error(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": "x"}}, UpdateExpression="DELETE #s :v",
        ExpressionAttributeNames=names, ExpressionAttributeValues={":v": {"NS": ["1", "2"]}},
    ))
    expected2 = "An operand in the update expression has an incorrect data type"
    assert (code2, message2) == ("ValidationException", expected2), (
        f"DELETE #s :v with a Number Set operand onto a String Set attribute raised "
        f"{(code2, message2)!r}, expected {('ValidationException', expected2)!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key={"pk": {"S": "x"}}, ConsistentRead=True)["Item"]
    assert set(unchanged["tags"]["SS"]) == {"a", "b"}, (
        f"both rejected DELETEs must leave the attribute untouched, got {unchanged['tags']!r}"
    )

    ddb.update_item(
        TableName=table, Key={"pk": {"S": "x"}}, UpdateExpression="DELETE #s :v",
        ExpressionAttributeNames=names, ExpressionAttributeValues={":v": {"SS": ["a"]}},
    )
    shrunk = ddb.get_item(TableName=table, Key={"pk": {"S": "x"}}, ConsistentRead=True)["Item"]
    assert set(shrunk["tags"]["SS"]) == {"b"}, (
        f"the positive-control same-typed DELETE must remove the named element, got {shrunk['tags']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
