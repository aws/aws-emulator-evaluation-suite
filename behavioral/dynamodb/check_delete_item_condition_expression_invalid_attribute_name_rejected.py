"""delete-item-condition-expression-invalid-attribute-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-item-condition-expression-invalid-attribute-name-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An accepted call raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteItem whose ConditionExpression cites an undeclared attribute name is rejected.

    The item survives the ValidationException; a properly declared condition deletes it.
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-diean-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "item-1"}}
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "item-1"}, "status": {"S": "active"}})

    # ConditionExpression references "#missing" but ExpressionAttributeNames never defines it.
    code, message = _error(
        lambda: ddb.delete_item(
            TableName=table_name,
            Key=key,
            ConditionExpression="#missing = :v",
            ExpressionAttributeNames={"#other": "status"},
            ExpressionAttributeValues={":v": {"S": "active"}},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_msg = (
        "1 validation error detected: Invalid ConditionExpression: An expression attribute name "
        "used in the document path is not defined; attribute name: #missing"
    )
    assert message == expected_msg, f"expected message {expected_msg!r}, got {message!r}"

    # Effect absent: the item was not deleted by the rejected call.
    item = ddb.get_item(TableName=table_name, Key=key, ConsistentRead=True)["Item"]
    assert item["status"]["S"] == "active"

    # Positive control: the same delete with a properly declared attribute name succeeds.
    ddb.delete_item(
        TableName=table_name,
        Key=key,
        ConditionExpression="#s = :v",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":v": {"S": "active"}},
    )
    resp = ddb.get_item(TableName=table_name, Key=key, ConsistentRead=True)
    assert "Item" not in resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
