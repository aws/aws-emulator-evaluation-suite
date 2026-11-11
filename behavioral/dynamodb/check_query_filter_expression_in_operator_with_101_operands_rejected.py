"""query-filter-expression-in-operator-with-101-operands-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "query-filter-expression-in-operator-with-101-operands-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]

_ROWS = (
    ("o1", "pending"),
    ("o2", "complete"),
    ("o3", "pending"),
)


def _error_code(fn) -> tuple:
    """The AWS (code, message) raised by fn(); raises if fn() unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query FilterExpression's IN operator rejects 101 operands with an exact
    ValidationException message; 100 operands is the accepted boundary and still matches.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbqin-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for sk, status in _ROWS:
        ddb.put_item(TableName=table, Item={"pk": {"S": "u1"}, "sk": {"S": sk}, "status": {"S": status}})

    operand_count = 101
    code, message = _error_code(lambda: ddb.query(
        TableName=table,
        KeyConditionExpression="pk = :pk",
        FilterExpression="#s IN (" + ", ".join(f":v{i}" for i in range(operand_count)) + ")",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":pk": {"S": "u1"},
            **{f":v{i}": {"S": f"x{i}"} for i in range(operand_count)},
        },
    ))
    expected_code = "ValidationException"
    expected_message = (
        f"Invalid FilterExpression: The IN operator is provided with too many operands; "
        f"number of operands: {operand_count}"
    )
    assert code == expected_code, f"the 101-operand IN raised {code!r}, expected {expected_code!r}"
    assert message == expected_message, (
        f"the 101-operand IN message was {message!r}, expected {expected_message!r}"
    )

    # Positive control: 100 operands, including the value that actually matches, still answers.
    vals = {f":v{i}": {"S": "pending" if i == 0 else f"x{i}"} for i in range(100)}
    ok = ddb.query(
        TableName=table,
        KeyConditionExpression="pk = :pk",
        FilterExpression="#s IN (" + ", ".join(vals) + ")",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":pk": {"S": "u1"}, **vals},
        ConsistentRead=True,
    )
    want = sum(1 for _, status in _ROWS if status == "pending")
    assert ok["Count"] == want, f"the 100-operand IN matched Count={ok['Count']!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
