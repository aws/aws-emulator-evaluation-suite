"""query-key-condition-expression-third-predicate-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-key-condition-expression-third-predicate-rejected"
GROUP = "access_path"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn) -> tuple:
    """The AWS error (code, message) fn() raises. Raises when the call SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it was accepted")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A KeyConditionExpression with a third ANDed clause, or a second clause naming a non-sort-key
    attribute, is rejected with ValidationException and its exact message, not applied as a filter.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-idx-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "createdAt", "AttributeType": "S"},
            {"AttributeName": "alternate", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        GlobalSecondaryIndexes=[{
            "IndexName": "status-index",
            "KeySchema": [{"AttributeName": "status", "KeyType": "HASH"}, {"AttributeName": "createdAt", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["summary"]},
        }],
        LocalSecondaryIndexes=[{
            "IndexName": "alternate-index",
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "alternate", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "KEYS_ONLY"},
        }],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Positive control: the identical two-predicate form (hash + range, both the GSI's
    # own key schema) is accepted, so the rejections below are shown to be about the
    # THIRD predicate, not about this wiring in general.
    control = ddb.query(
        TableName=t,
        IndexName="status-index",
        KeyConditionExpression="#s = :status AND #c > :createdAt",
        ExpressionAttributeNames={"#s": "status", "#c": "createdAt"},
        ExpressionAttributeValues={":status": {"S": "open"}, ":createdAt": {"S": "2020-01-01"}},
    )
    assert control["Count"] == 0, f"positive control: expected 0 items on an empty index, got {control['Count']}"

    # Two predicates: the index hash key ANDed with a clause naming a real attribute that is NOT
    # this index's sort key (it is the LSI's). The second clause is read as the sort-key condition,
    # so the refusal names the sort key it expected.
    code, message = _error(lambda: ddb.query(
        TableName=t,
        IndexName="status-index",
        KeyConditionExpression="#s = :status AND alternate = :alternate",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":status": {"S": "open"}, ":alternate": {"S": "a1"}},
    ))
    assert code == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code} ({message!r})"
    expected = "Query condition missed key schema element: createdAt"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Three predicates: hash, range, and a third ANDed clause.
    code2, message2 = _error(lambda: ddb.query(
        TableName=t,
        IndexName="status-index",
        KeyConditionExpression="#s = :status AND #c > :createdAt AND alternate = :alternate",
        ExpressionAttributeNames={"#s": "status", "#c": "createdAt"},
        ExpressionAttributeValues={
            ":status": {"S": "open"},
            ":createdAt": {"S": "2020-01-01"},
            ":alternate": {"S": "a1"},
        },
    ))
    assert code2 == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code2} ({message2!r})"
    expected2 = (
        "The number of query conditions (3) exceeds the number of key attributes defined in the "
        "schema (2)"
    )
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"

    # Final control: the two-predicate form still works after both rejections above.
    control_after = ddb.query(
        TableName=t,
        IndexName="status-index",
        KeyConditionExpression="#s = :status",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":status": {"S": "open"}},
    )
    assert control_after["Count"] == 0, (
        f"positive control after rejections: expected 0 items, got {control_after['Count']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
