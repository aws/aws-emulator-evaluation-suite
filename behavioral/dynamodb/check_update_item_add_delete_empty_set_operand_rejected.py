"""update-item-add-delete-empty-set-operand-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-add-delete-empty-set-operand-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]
_EMPTY_SET = (
    "ValidationException",
    "1 validation error detected: One or more parameter values were invalid: "
    "An string set  may not be empty",
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
    """UpdateItem's ADD and DELETE actions both reject a set operand with zero members, leaving
    the target attribute unchanged; a same-typed operand with members still applies.
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
    ddb.put_item(TableName=table, Item={**key, "tags": {"SS": ["only"]}})

    expect_error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD tags :e",
        ExpressionAttributeValues={":e": {"SS": []}},
    ), *_EMPTY_SET)

    expect_error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE tags :e",
        ExpressionAttributeValues={":e": {"SS": []}},
    ), *_EMPTY_SET)

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged["tags"]["SS"] == ["only"], (
        f"both rejected calls must leave the attribute untouched, got {unchanged['tags']!r}"
    )

    # Positive control: the same operand shape with a member applies.
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD tags :e",
        ExpressionAttributeValues={":e": {"SS": ["more"]}},
    )
    grown = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert set(grown["tags"]["SS"]) == {"only", "more"}, (
        f"the positive-control ADD with a non-empty set must apply, got {grown['tags']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
