"""query-filter-expression-between-reversed-bounds-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-filter-expression-between-reversed-bounds-rejected"
GROUP = "query"
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
    """A Query FilterExpression's BETWEEN with its lower bound above its upper bound is
    rejected with ValidationException before any item is examined, while the same bounds in
    ascending order select the matching items.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for sk, score in (("i1", "5"), ("i2", "15"), ("i3", "30")):
        ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": sk}, "score": {"N": score}})

    # Positive control: the same bounds in ascending order parse and select the one item
    # (score=15) that falls inside [10, 25].
    ok = ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="pk = :pk",
        FilterExpression="#sc BETWEEN :lo AND :hi",
        ExpressionAttributeNames={"#sc": "score"},
        ExpressionAttributeValues={":pk": {"S": "p1"}, ":lo": {"N": "10"}, ":hi": {"N": "25"}},
    )
    got = sorted(i["sk"]["S"] for i in ok["Items"])
    assert got == ["i2"], f"the ascending-bounds control returned {got!r}, expected ['i2']"

    code, message = _error(lambda: ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="pk = :pk",
        FilterExpression="#sc BETWEEN :hi AND :lo",
        ExpressionAttributeNames={"#sc": "score"},
        ExpressionAttributeValues={":pk": {"S": "p1"}, ":lo": {"N": "10"}, ":hi": {"N": "25"}},
    ))
    assert code == ERR_VALIDATION, f"the reversed-bounds Query was refused with {code!r}, expected {ERR_VALIDATION!r}"
    expected_message = (
        "Invalid FilterExpression: The BETWEEN operator requires upper bound to be greater "
        "than or equal to lower bound; lower bound operand: AttributeValue: {N:25}, upper "
        "bound operand: AttributeValue: {N:10}"
    )
    assert message == expected_message, f"unexpected message for the reversed BETWEEN: {message!r}"

    # After the rejection the table still answers the control exactly as before.
    again = ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="pk = :pk",
        FilterExpression="#sc BETWEEN :lo AND :hi",
        ExpressionAttributeNames={"#sc": "score"},
        ExpressionAttributeValues={":pk": {"S": "p1"}, ":lo": {"N": "10"}, ":hi": {"N": "25"}},
    )
    got_again = sorted(i["sk"]["S"] for i in again["Items"])
    assert got_again == ["i2"], f"after the rejection the control returned {got_again!r}, expected ['i2']"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
