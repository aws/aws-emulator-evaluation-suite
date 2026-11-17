"""update-expression-add-delete-duplicate-set-operand-members-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-expression-add-delete-duplicate-set-operand-members-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]

_ADD_DUP_SS = (
    "ValidationException",
    '1 validation error detected: One or more parameter values were invalid: '
    'Input collection ["dup", "dup"] contains duplicates.',
)
_DELETE_DUP_BS = (
    "ValidationException",
    '1 validation error detected: One or more parameter values were invalid: '
    'Input collection ["bm8=","bm8="]of type BS contains duplicates.',
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
    """UpdateItem's ADD and DELETE each reject a set operand literal that repeats a member,
    leaving the attribute untouched; a same-shaped operand with no repeat still applies.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
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

    key = {"pk": {"S": "item"}}
    ddb.put_item(TableName=table, Item={**key, "tags": {"SS": ["one"]}, "bins": {"BS": [b"aa"]}})

    expect_error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD tags :v",
        ExpressionAttributeValues={":v": {"SS": ["dup", "dup"]}},
    ), *_ADD_DUP_SS)

    expect_error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE bins :v",
        ExpressionAttributeValues={":v": {"BS": [b"no", b"no"]}},
    ), *_DELETE_DUP_BS)

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged["tags"] == {"SS": ["one"]}, (
        f"the rejected ADD must leave the String Set untouched, got {unchanged['tags']!r}"
    )
    assert set(unchanged["bins"]["BS"]) == {b"aa"}, (
        f"the rejected DELETE must leave the Binary Set untouched, got {unchanged['bins']!r}"
    )

    # Positive control: the identical shape of operand, with no repeated member, applies.
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD tags :v",
        ExpressionAttributeValues={":v": {"SS": ["two"]}},
    )
    grown = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert set(grown["tags"]["SS"]) == {"one", "two"}, (
        f"the positive-control ADD with no repeated member must apply, got {grown['tags']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
