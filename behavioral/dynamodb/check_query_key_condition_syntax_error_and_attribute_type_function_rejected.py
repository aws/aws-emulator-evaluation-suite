"""query-key-condition-syntax-error-and-attribute-type-function-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-key-condition-syntax-error-and-attribute-type-function-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn) -> tuple:
    """The (code, message) of the ClientError fn() raises. RAISES when fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query KeyConditionExpression rejects a grammar syntax error (a dangling AND, a stray
    double-equals) and the attribute_type function, each with its own exact message; the legal
    Query still succeeds.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-qkcs-")
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
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={"pk": {"S": "p"}, "sk": {"S": "a"}})

    # (1) A dangling AND with nothing after it -- a grammar syntax error, not a semantic one.
    code, message = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="pk = :p AND",
        ExpressionAttributeValues={":p": {"S": "p"}},
    ))
    assert code == ERR_VALIDATION, f"dangling AND answered {code!r} ({message!r}), expected {ERR_VALIDATION}"
    expected_dangling = 'Invalid KeyConditionExpression: Syntax error; token: "<EOF>", near: "AND"'
    assert message == expected_dangling, f"expected message {expected_dangling!r}, got {message!r}"

    # (2) A stray repeated operator -- a token the grammar never accepts there.
    code2, message2 = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="pk = = :p",
        ExpressionAttributeValues={":p": {"S": "p"}},
    ))
    assert code2 == ERR_VALIDATION, f"stray '=' answered {code2!r} ({message2!r}), expected {ERR_VALIDATION}"
    expected_stray = 'Invalid KeyConditionExpression: Syntax error; token: "=", near: "= = :p"'
    assert message2 == expected_stray, f"expected message {expected_stray!r}, got {message2!r}"

    # (3) attribute_type is a function the condition-expression grammar supports generally, but
    # a KeyConditionExpression permits only begins_with and BETWEEN beyond a plain comparison;
    # AWS reports it the same way as any other operator a key condition does not allow.
    code3, message3 = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="attribute_type(pk, :t)",
        ExpressionAttributeValues={":t": {"S": "S"}},
    ))
    assert code3 == ERR_VALIDATION, f"attribute_type() answered {code3!r} ({message3!r}), expected {ERR_VALIDATION}"
    expected_fn = "Invalid KeyConditionExpression: Invalid operator used in KeyConditionExpression"
    assert message3 == expected_fn, f"expected message {expected_fn!r}, got {message3!r}"

    # Positive control: the legal form over the same partition still works after all three
    # rejections, and none of them reached the table.
    control = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p",
        ExpressionAttributeValues={":p": {"S": "p"}}, ConsistentRead=True,
    )
    assert control["Count"] == 1, f"expected Count 1 for the legal Query, got {control['Count']}"
    assert control["Items"] == [{"pk": {"S": "p"}, "sk": {"S": "a"}}], (
        f"expected only the original item, got {control['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
