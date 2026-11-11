"""query-key-condition-duplicate-sort-key-clause-and-nested-path-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-key-condition-duplicate-sort-key-clause-and-nested-path-rejected"
GROUP = "access_path"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn) -> tuple:
    """The AWS error (code, message) fn() raises. Raises when the call SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A KeyConditionExpression naming the sort key in two ANDed clauses (a range split across
    two comparisons rather than BETWEEN) is rejected, and so is one addressing a key attribute
    through a nested path; neither reaches the table.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-")
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
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    ddb.put_item(TableName=table, Item={"pk": {"S": "p"}, "sk": {"S": "m"}})

    # Positive control: the same partition, a legal single-clause-per-key condition, succeeds.
    control = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p AND sk > :lo",
        ExpressionAttributeValues={":p": {"S": "p"}, ":lo": {"S": "a"}},
        ConsistentRead=True,
    )
    assert control["Count"] == 1, f"positive control: expected 1 item, got {control['Count']}"

    # Two ANDed clauses both naming the sort key (a hand-rolled range instead of BETWEEN).
    code, message = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="pk = :p AND sk > :lo AND sk < :hi",
        ExpressionAttributeValues={":p": {"S": "p"}, ":lo": {"S": "a"}, ":hi": {"S": "z"}},
    ))
    assert code == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code} ({message!r})"
    expected_duplicate = "Invalid KeyConditionExpression: KeyConditionExpressions must only contain one condition per key"
    assert message == expected_duplicate, f"expected message {expected_duplicate!r}, got {message!r}"

    # A nested path (#sk.x) addressing the sort key, which is a scalar, not a document.
    code2, message2 = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="pk = :p AND #s.x = :v",
        ExpressionAttributeNames={"#s": "sk"},
        ExpressionAttributeValues={":p": {"S": "p"}, ":v": {"S": "y"}},
    ))
    assert code2 == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code2} ({message2!r})"
    expected_nested = "Invalid KeyConditionExpression: KeyConditionExpressions cannot have conditions on nested attributes"
    assert message2 == expected_nested, f"expected message {expected_nested!r}, got {message2!r}"

    # A nested path (#pk.x) addressing the partition key is rejected the same way.
    code3, message3 = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="#p.x = :p AND sk = :v",
        ExpressionAttributeNames={"#p": "pk"},
        ExpressionAttributeValues={":p": {"S": "p"}, ":v": {"S": "m"}},
    ))
    assert code3 == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code3} ({message3!r})"
    assert message3 == expected_nested, f"expected message {expected_nested!r}, got {message3!r}"

    # Read back: the table still holds exactly the one item the positive control proved,
    # never more (nothing the three rejected calls would have written) and never less.
    final = ddb.scan(TableName=table, ConsistentRead=True)
    assert final["Count"] == 1, f"expected the table unchanged at 1 item, got {final['Count']}"
    assert final["Items"] == [{"pk": {"S": "p"}, "sk": {"S": "m"}}], (
        f"expected only the original item, got {final['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
