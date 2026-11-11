"""query-unbalanced-nested-key-condition-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-unbalanced-nested-key-condition-rejected"
GROUP = "access_path"
SERVICES = ["dynamodb"]

_SYNTAX_ERROR = (
    "ValidationException",
    'Invalid KeyConditionExpression: Syntax error; token: "<EOF>", near: ")"',
)


def _expect_error(fn, code: str, message: str) -> None:
    """Raises on an unexpected success; otherwise asserts the exact (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == code, f"expected code {code!r}, got {err.get('Code')!r}"
        assert err.get("Message") == message, (
            f"expected message {message!r}, got {err.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected the call to be refused with {code}, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query KeyConditionExpression whose nested parentheses are unbalanced is refused
    with a ValidationException naming the syntax error; the balanced form returns the item.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "s1"}})

    # Positive control: the balanced nested form (inner paren wraps just the sort-key
    # clause) is accepted, so the rejection below is shown to be about the missing
    # closing paren, not about nesting in general.
    control = ddb.query(
        TableName=t,
        KeyConditionExpression="(pk = :p AND (sk = :s))",
        ExpressionAttributeValues={":p": {"S": "p1"}, ":s": {"S": "s1"}},
        ConsistentRead=True,
    )
    assert control["Count"] == 1, f"positive control: expected 1 item, got {control['Count']}"

    # The inner paren around the sort-key clause is never closed.
    _expect_error(
        lambda: ddb.query(
            TableName=t,
            KeyConditionExpression="(pk = :p AND (sk = :s)",
            ExpressionAttributeValues={":p": {"S": "p1"}, ":s": {"S": "s1"}},
            ConsistentRead=True,
        ),
        *_SYNTAX_ERROR,
    )

    # Final control: the balanced nested form still works after the rejection above.
    control_after = ddb.query(
        TableName=t,
        KeyConditionExpression="(pk = :p AND (sk = :s))",
        ExpressionAttributeValues={":p": {"S": "p1"}, ":s": {"S": "s1"}},
        ConsistentRead=True,
    )
    assert control_after["Count"] == 1, (
        f"positive control after rejection: expected 1 item, got {control_after['Count']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
