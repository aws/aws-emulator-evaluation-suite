"""update-item-add-string-set-onto-scalar-string-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-add-string-set-onto-scalar-string-rejected"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_INCORRECT_OPERAND_TYPE = (
    "ValidationException",
    "An operand in the update expression has an incorrect data type",
)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem ADD of a String Set value onto an existing scalar String attribute is
    rejected with ValidationException and leaves the attribute unchanged, while an ADD of a
    same-typed String Set value onto a sibling String Set attribute still succeeds.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx)

    pk = ctx.unique_name("item-")
    ddb.put_item(
        TableName=table,
        Item={
            "pk": {"S": pk},
            "tag": {"S": "not-a-set"},
            "tags": {"SS": ["a", "b"]},
        },
    )

    # Positive control: ADD of a String Set onto a sibling String Set attribute succeeds.
    ddb.update_item(
        TableName=table,
        Key={"pk": {"S": pk}},
        UpdateExpression="ADD tags :s",
        ExpressionAttributeValues={":s": {"SS": ["c"]}},
    )
    item = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
    assert set(item["tags"]["SS"]) == {"a", "b", "c"}, (
        f"positive-control ADD did not apply, got {item.get('tags')!r}"
    )

    expect_error(
        lambda: ddb.update_item(
            TableName=table,
            Key={"pk": {"S": pk}},
            UpdateExpression="ADD tag :s",
            ExpressionAttributeValues={":s": {"SS": ["x"]}},
        ),
        *_INCORRECT_OPERAND_TYPE,
    )

    # Effect absent: both attributes are untouched by the rejected mismatched ADD.
    item = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
    assert item["tag"] == {"S": "not-a-set"}, (
        f"rejected ADD must leave the scalar String attribute untouched, got {item.get('tag')!r}"
    )
    assert set(item["tags"]["SS"]) == {"a", "b", "c"}, (
        f"rejected ADD on one attribute must not affect a sibling attribute, got {item.get('tags')!r}"
    )


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
