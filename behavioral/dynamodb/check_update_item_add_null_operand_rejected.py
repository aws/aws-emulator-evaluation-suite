"""update-item-add-null-operand-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-add-null-operand-rejected"
GROUP = "scalar-types"
SERVICES = ["dynamodb"]

_ADD_NULL_OPERAND = (
    "ValidationException",
    "1 validation error detected: Invalid UpdateExpression: Incorrect operand type for operator "
    "or function; operator: ADD, operand type: NULL, typeSet: ALLOWED_FOR_ADD_OPERAND",
)


def expect_error(fn, code, message):
    """Call fn() and assert the ClientError it raises carries exactly code and message."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, f"expected {code!r}, got {err.get('Code')!r}: {err.get('Message')!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return exc
    raise AssertionError(f"expected {code!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateExpression ADD refuses a NULL-typed operand, leaves the attribute untouched, and a
    same-typed ADD still applies.
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

    key = {"pk": {"S": "x"}}
    ddb.put_item(TableName=table, Item={**key, "tally": {"N": "10"}})
    names = {"#t": "tally"}

    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=key, UpdateExpression="ADD #t :v",
            ExpressionAttributeNames=names, ExpressionAttributeValues={":v": {"NULL": True}},
        ),
        *_ADD_NULL_OPERAND,
    )

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged["tally"] == {"N": "10"}, (
        f"the rejected ADD must leave the attribute untouched, got {unchanged['tally']!r}"
    )

    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD #t :v",
        ExpressionAttributeNames=names, ExpressionAttributeValues={":v": {"N": "5"}},
    )
    bumped = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert bumped["tally"] == {"N": "15"}, (
        f"the positive-control same-typed ADD must apply, got {bumped['tally']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
