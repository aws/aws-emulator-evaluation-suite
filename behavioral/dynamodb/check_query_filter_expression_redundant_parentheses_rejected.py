"""query-filter-expression-redundant-parentheses-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-filter-expression-redundant-parentheses-rejected"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_REDUNDANT_PARENS = (
    "ValidationException",
    "Invalid FilterExpression: The expression has redundant parentheses;",
)


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query FilterExpression doubly wrapping the same clause in parentheses is
    rejected as redundant, both around a comparison and around a function call, while
    a single wrap of either form still evaluates.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-ddbqrp-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                   {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={"pk": {"S": "grp"}, "sk": {"S": "a"}, "category": {"S": "A"}})

    expect_error(
        lambda: ddb.query(
            TableName=table, ConsistentRead=True, KeyConditionExpression="pk = :p",
            FilterExpression="((category = :c))",
            ExpressionAttributeValues={":p": {"S": "grp"}, ":c": {"S": "A"}},
        ),
        *_REDUNDANT_PARENS,
    )
    expect_error(
        lambda: ddb.query(
            TableName=table, ConsistentRead=True, KeyConditionExpression="pk = :p",
            FilterExpression="((begins_with(category, :c)))",
            ExpressionAttributeValues={":p": {"S": "grp"}, ":c": {"S": "A"}},
        ),
        *_REDUNDANT_PARENS,
    )

    control = ddb.query(
        TableName=table, ConsistentRead=True, KeyConditionExpression="pk = :p",
        FilterExpression="(category = :c)",
        ExpressionAttributeValues={":p": {"S": "grp"}, ":c": {"S": "A"}},
    )
    assert control["Count"] == 1, (
        f"the single-wrapped equivalent returned Count={control['Count']}, expected 1"
    )
    assert control["Items"][0]["sk"] == {"S": "a"}, (
        f"the single-wrapped equivalent returned sk={control['Items'][0].get('sk')!r}, expected 'a'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
