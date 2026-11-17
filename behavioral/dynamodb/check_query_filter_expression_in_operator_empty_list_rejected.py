"""query-filter-expression-in-operator-empty-list-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-filter-expression-in-operator-empty-list-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]


def _error(fn) -> tuple:
    """The (code, message) ``fn`` is refused with. An unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query FilterExpression's IN with an empty operand list is rejected with
    ValidationException before any item is examined, while a one-value list parses and selects
    the matching item.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": "i1"}, "score": {"N": "9"}})

    # Positive control: a one-value IN list parses and selects the matching item.
    ok = ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="#pk = :pk",
        FilterExpression="#sc IN (:a)",
        ExpressionAttributeNames={"#pk": "pk", "#sc": "score"},
        ExpressionAttributeValues={":pk": {"S": "p1"}, ":a": {"N": "9"}},
    )
    got = sorted(i["sk"]["S"] for i in ok["Items"])
    assert got == ["i1"], f"the one-value IN control returned {got!r}, expected ['i1']"

    code, message = _error(lambda: ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="#pk = :pk",
        FilterExpression="#sc IN ()",
        ExpressionAttributeNames={"#pk": "pk", "#sc": "score"},
        ExpressionAttributeValues={":pk": {"S": "p1"}},
    ))
    _EMPTY_IN = ("ValidationException", 'Invalid FilterExpression: Syntax error; token: ")", near: "()"')
    assert (code, message) == _EMPTY_IN, f"empty IN list was refused with {(code, message)!r}, expected {_EMPTY_IN!r}"

    # The item is unaffected by the rejected filter: a direct read still returns it unchanged.
    after = ddb.get_item(TableName=table, Key={"pk": {"S": "p1"}, "sk": {"S": "i1"}}, ConsistentRead=True)
    assert after["Item"]["score"] == {"N": "9"}, (
        f"item score after the rejected Query was {after['Item']['score']!r}, expected unchanged {{'N': '9'}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
