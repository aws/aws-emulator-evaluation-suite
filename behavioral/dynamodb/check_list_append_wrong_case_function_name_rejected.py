"""list-append-wrong-case-function-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-append-wrong-case-function-name-rejected"
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
    """UpdateItem's expression functions are case-sensitive: `LIST_APPEND` is an unrecognized
    function name and is refused, leaving the list untouched; `list_append` still applies.
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
    ddb.put_item(TableName=table, Item={"pk": {"S": "x"}, "l": {"L": [{"S": "a"}]}})

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": "x"}}, UpdateExpression="SET #l = LIST_APPEND(#l, :v)",
        ExpressionAttributeNames={"#l": "l"}, ExpressionAttributeValues={":v": {"L": [{"S": "b"}]}},
    ))
    expected = "1 validation error detected: Invalid UpdateExpression: Invalid function name; function: LIST_APPEND"
    assert (code, message) == ("ValidationException", expected), (
        f"SET with LIST_APPEND (wrong case) raised {(code, message)!r}, expected "
        f"{('ValidationException', expected)!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key={"pk": {"S": "x"}}, ConsistentRead=True)["Item"]
    assert unchanged["l"]["L"] == [{"S": "a"}], (
        f"the rejected LIST_APPEND must not change the list, got {unchanged['l']!r}"
    )

    ddb.update_item(
        TableName=table, Key={"pk": {"S": "x"}}, UpdateExpression="SET #l = list_append(#l, :v)",
        ExpressionAttributeNames={"#l": "l"}, ExpressionAttributeValues={":v": {"L": [{"S": "b"}]}},
    )
    grown = ddb.get_item(TableName=table, Key={"pk": {"S": "x"}}, ConsistentRead=True)["Item"]
    assert grown["l"]["L"] == [{"S": "a"}, {"S": "b"}], (
        f"the positive-control list_append (correct case) must append, got {grown['l']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
