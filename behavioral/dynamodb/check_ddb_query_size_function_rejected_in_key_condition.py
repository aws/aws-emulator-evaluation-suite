"""ddb-query-size-function-rejected-in-key-condition."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ddb-query-size-function-rejected-in-key-condition"
GROUP = "query"
SERVICES = ["dynamodb"]

_NESTED_OP = ("ValidationException", "Invalid KeyConditionExpression: KeyConditionExpressions cannot contain nested operations")


def expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert (err["Code"], err["Message"]) == (code, message), (
            f"got ({err['Code']!r}, {err['Message']!r}), expected ({code!r}, {message!r})"
        )
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query KeyConditionExpression refuses size() -- a function call is a nested operation
    there -- while size() on a non-key attribute still succeeds in that same Query's
    FilterExpression.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbkcs-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                               {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={"pk": {"S": "probe"}, "sk": {"S": "ab"}, "tag": {"S": "xy"}})

    expect_error(
        lambda: ddb.query(
            TableName=table, KeyConditionExpression="size(pk) = :n",
            ExpressionAttributeValues={":n": {"N": "5"}},
        ),
        *_NESTED_OP,
    )

    control = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p", ConsistentRead=True,
        FilterExpression="size(tag) = :n",
        ExpressionAttributeValues={":p": {"S": "probe"}, ":n": {"N": "2"}},
    )
    assert {i["sk"]["S"] for i in control["Items"]} == {"ab"}, (
        f"the same size() shape in a FilterExpression must still select the item, got {control['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
