"""query-base-table-primary-key-in-filter-expression-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-base-table-primary-key-in-filter-expression-rejected"
GROUP = "access_path"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn) -> tuple:
    """The (code, message) ``fn`` is refused with. An unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A base-table Query whose FilterExpression names the table's own hash or range key raises
    ValidationException naming that attribute, while a filter on a non-key attribute matches.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "s1"}, "status": {"S": "ok"}})

    # Positive control: the same query shape with a FilterExpression on a non-key attribute
    # matches the seeded item, so the refusals below are about the selected key, not the
    # call shape or FilterExpression itself.
    control = ddb.query(
        TableName=t, KeyConditionExpression="pk = :p", FilterExpression="#s = :v",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":p": {"S": "p1"}, ":v": {"S": "ok"}},
    )
    assert control["Count"] == 1, f"positive control: expected the seeded item, got Count={control['Count']}"

    code, message = _error(lambda: ddb.query(
        TableName=t, KeyConditionExpression="pk = :p", FilterExpression="pk = :p2",
        ExpressionAttributeValues={":p": {"S": "p1"}, ":p2": {"S": "p1"}},
    ))
    assert code == ERR_VALIDATION, f"hash key in FilterExpression: expected {ERR_VALIDATION}, got {code}: {message!r}"
    assert message == "Filter Expression can only contain non-primary key attributes: Primary key attribute: pk", (
        f"hash key in FilterExpression: unexpected message {message!r}"
    )

    code, message = _error(lambda: ddb.query(
        TableName=t, KeyConditionExpression="pk = :p", FilterExpression="sk = :s",
        ExpressionAttributeValues={":p": {"S": "p1"}, ":s": {"S": "s1"}},
    ))
    assert code == ERR_VALIDATION, f"range key in FilterExpression: expected {ERR_VALIDATION}, got {code}: {message!r}"
    assert message == "Filter Expression can only contain non-primary key attributes: Primary key attribute: sk", (
        f"range key in FilterExpression: unexpected message {message!r}"
    )

    # Nothing either rejected call could have written: the table still holds only the seed.
    final = ddb.scan(TableName=t, ConsistentRead=True)["Items"]
    assert final == [{"pk": {"S": "p1"}, "sk": {"S": "s1"}, "status": {"S": "ok"}}], (
        f"expected only the seed item to remain, got {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
