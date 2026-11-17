"""update-item-nested-function-operand-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-nested-function-operand-rejected"
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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem rejects list_append nested inside list_append, and if_not_exists given a
    nested if_not_exists instead of a document path as its first operand; if_not_exists
    nested as list_append's first operand still applies.
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
    ddb.put_item(TableName=table, Item={"pk": {"S": "x"}, "l": {"L": [{"N": "1"}]}})

    nested_prefix = "1 validation error detected: Invalid UpdateExpression: "

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": "x"}},
        UpdateExpression="SET #l = list_append(list_append(#l, :a), :b)",
        ExpressionAttributeNames={"#l": "l"},
        ExpressionAttributeValues={":a": {"L": [{"N": "2"}]}, ":b": {"L": [{"N": "3"}]}},
    ))
    expected_nested_list_append = (
        nested_prefix + "The function is not allowed to be used this way in an expression; "
        "function: list_append"
    )
    assert (code, message) == ("ValidationException", expected_nested_list_append), (
        f"list_append nested inside list_append raised {(code, message)!r}, expected "
        f"{('ValidationException', expected_nested_list_append)!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key={"pk": {"S": "x"}}, ConsistentRead=True)["Item"]
    assert unchanged["l"]["L"] == [{"N": "1"}], (
        f"the rejected nested list_append must not change the list, got {unchanged['l']!r}"
    )

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": "x"}},
        UpdateExpression="SET #l = if_not_exists(if_not_exists(#l, :a), :b)",
        ExpressionAttributeNames={"#l": "l"},
        ExpressionAttributeValues={":a": {"L": [{"N": "2"}]}, ":b": {"L": [{"N": "3"}]}},
    ))
    expected_nested_if_not_exists = (
        nested_prefix + "Operator or function requires a document path; "
        "operator or function: if_not_exists"
    )
    assert (code, message) == ("ValidationException", expected_nested_if_not_exists), (
        f"if_not_exists nested as its own first operand raised {(code, message)!r}, expected "
        f"{('ValidationException', expected_nested_if_not_exists)!r}"
    )

    still_unchanged = ddb.get_item(TableName=table, Key={"pk": {"S": "x"}}, ConsistentRead=True)["Item"]
    assert still_unchanged["l"]["L"] == [{"N": "1"}], (
        f"the rejected nested if_not_exists must not change the list, got {still_unchanged['l']!r}"
    )

    ddb.update_item(
        TableName=table, Key={"pk": {"S": "x"}},
        UpdateExpression="SET #m = list_append(if_not_exists(#m, :empty), :c)",
        ExpressionAttributeNames={"#m": "m"},
        ExpressionAttributeValues={":empty": {"L": []}, ":c": {"L": [{"N": "9"}]}},
    )
    grown = ddb.get_item(TableName=table, Key={"pk": {"S": "x"}}, ConsistentRead=True)["Item"]
    assert grown["m"]["L"] == [{"N": "9"}], (
        f"list_append nested inside if_not_exists's own first operand must apply, got {grown['m']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
