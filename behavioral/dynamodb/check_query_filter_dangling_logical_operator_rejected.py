"""query-filter-dangling-logical-operator-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-filter-dangling-logical-operator-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"

_PK = "pk"
_SK = "sk"
_PART = "p1"


def _error(fn) -> tuple:
    """The (code, message) of the ClientError ``fn()`` raises. Raises when it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query FilterExpression rejects a dangling AND and a stray repeated AND as grammar
    syntax errors, each with its own exact message; the legal filter still succeeds.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": _PK, "KeyType": "HASH"}, {"AttributeName": _SK, "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": _PK, "AttributeType": "S"},
                              {"AttributeName": _SK, "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={_PK: {"S": _PART}, _SK: {"S": "i1"}, "status": {"S": "active"}})

    base = dict(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="#pk = :pk",
        ExpressionAttributeNames={"#pk": _PK, "#s": "status"},
        ExpressionAttributeValues={":pk": {"S": _PART}, ":a": {"S": "active"}},
    )

    # (1) A dangling AND with nothing after it -- a grammar syntax error, not a semantic one.
    code, message = _error(lambda: ddb.query(**base, FilterExpression="#s = :a AND"))
    assert code == ERR_VALIDATION, f"dangling AND answered {code!r} ({message!r}), expected {ERR_VALIDATION}"
    expected_dangling = 'Invalid FilterExpression: Syntax error; token: "<EOF>", near: "AND"'
    assert message == expected_dangling, f"expected message {expected_dangling!r}, got {message!r}"

    # (2) A stray repeated AND -- a token the grammar never accepts there.
    code2, message2 = _error(lambda: ddb.query(**base, FilterExpression="#s = :a AND AND #s = :a"))
    assert code2 == ERR_VALIDATION, f"stray AND answered {code2!r} ({message2!r}), expected {ERR_VALIDATION}"
    expected_stray = 'Invalid FilterExpression: Syntax error; token: "AND", near: "AND AND #s"'
    assert message2 == expected_stray, f"expected message {expected_stray!r}, got {message2!r}"

    # Positive control: the legal filter over the same partition still works after both
    # rejections, and neither reached the table.
    control = ddb.query(**base, FilterExpression="#s = :a")
    assert control["Count"] == 1, f"expected Count 1 for the legal filter, got {control['Count']}"
    assert control["Items"] == [{_PK: {"S": _PART}, _SK: {"S": "i1"}, "status": {"S": "active"}}], (
        f"expected only the original item, got {control['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
