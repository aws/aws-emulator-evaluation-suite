"""delete-item-expected-and-conditionexpression-mutually-exclusive-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-expected-and-conditionexpression-mutually-exclusive-rejected"
GROUP = "errors"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteItem supplying both the legacy Expected and ConditionExpression is rejected with
    ValidationException and its exact message, while ConditionExpression alone deletes the item.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-delexpr-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={"pk": {"S": "x"}})

    try:
        ddb.delete_item(
            TableName=table, Key={"pk": {"S": "x"}},
            Expected={"pk": {"Exists": True}},
            ConditionExpression="attribute_exists(pk)",
        )
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code}"
    expected_message = (
        "1 validation error detected: Can not use both expression and non-expression parameters "
        "in the same request: Non-expression parameters: {Expected} Expression parameters: "
        "{ConditionExpression}"
    )
    assert message == expected_message, f"expected AWS's exact message, got {message!r}"
    assert ddb.get_item(TableName=table, Key={"pk": {"S": "x"}}, ConsistentRead=True).get("Item") is not None, (
        "the rejected DeleteItem must not have removed the item"
    )

    ddb.delete_item(TableName=table, Key={"pk": {"S": "x"}}, ConditionExpression="attribute_exists(pk)")
    assert ddb.get_item(TableName=table, Key={"pk": {"S": "x"}}, ConsistentRead=True).get("Item") is None, (
        "positive control: ConditionExpression alone must delete the item"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
