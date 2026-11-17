"""query-key-condition-expression-contains-function-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-key-condition-expression-contains-function-rejected"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_ERR_VALIDATION = "ValidationException"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query refuses a KeyConditionExpression naming contains(), the function being valid only
    in a FilterExpression; the same attribute admits the matching read via FilterExpression.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbqkc-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    pk = "p"
    ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "sk": {"S": "s1"}})

    code, message = _error(lambda: ddb.query(
        TableName=table,
        KeyConditionExpression="contains(pk, :v)",
        ExpressionAttributeValues={":v": {"S": pk}},
    ))
    assert code == _ERR_VALIDATION, f"expected {_ERR_VALIDATION}, got {code}: {message!r}"
    assert message == (
        "Invalid KeyConditionExpression: Invalid operator used in KeyConditionExpression"
    ), f"unexpected message for contains() in KeyConditionExpression: {message!r}"

    # Positive control: the same partition key equality, through the operator KeyConditionExpression
    # actually accepts, still finds the item.
    resp = ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="pk = :v",
        ExpressionAttributeValues={":v": {"S": pk}},
    )
    sks = frozenset(i["sk"]["S"] for i in resp["Items"])
    assert sks == frozenset({"s1"}), f"'pk = :v' returned {sorted(sks)!r}, expected only 's1'"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
