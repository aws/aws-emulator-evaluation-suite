"""query-filter-expression-ordering-comparison-non-orderable-operand-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-filter-expression-ordering-comparison-non-orderable-operand-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]

_OPERAND_TYPE_MSG = (
    "Invalid FilterExpression: Incorrect operand type for operator or function; "
    "operator or function: {op}, operand type: {op_type}"
)

_NON_ORDERABLE = {"BOOL": {"BOOL": True}, "NULL": {"NULL": True}}


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; RAISES if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query FilterExpression's <= and >= refuse a BOOL or NULL operand with ValidationException,
    and leave the partition's content exactly as queried before the rejected calls.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-queryord-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": "item1"}, "score": {"N": "10"}})
    ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": "item2"}, "score": {"N": "20"}})

    def _query_compare(op, operand_value):
        return ddb.query(
            TableName=table,
            KeyConditionExpression="pk = :pk",
            FilterExpression=f"score {op} :v",
            ExpressionAttributeValues={":pk": {"S": "p1"}, ":v": operand_value},
            ConsistentRead=True,
        )

    for op in ("<=", ">="):
        for op_type, operand in _NON_ORDERABLE.items():
            code, message = _error(lambda: _query_compare(op, operand))
            assert code == "ValidationException", (
                f"'score {op} :v' with a {op_type} operand answered {code!r}, expected "
                f"ValidationException"
            )
            expected_message = _OPERAND_TYPE_MSG.format(op=op, op_type=op_type)
            assert message == expected_message, (
                f"'score {op} :v' with a {op_type} operand said {message!r}, expected "
                f"{expected_message!r}"
            )

    unfiltered = ddb.query(
        TableName=table, KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": {"S": "p1"}}, ConsistentRead=True,
    )
    assert unfiltered["Count"] == 2, (
        f"after the rejected comparisons the partition held {unfiltered['Count']} item(s), expected "
        f"2: the rejected filter calls must not have written or removed anything"
    )

    # Positive control: the same operator over a correctly-typed N operand still filters normally.
    le = ddb.query(
        TableName=table, KeyConditionExpression="pk = :pk", FilterExpression="score <= :v",
        ExpressionAttributeValues={":pk": {"S": "p1"}, ":v": {"N": "10"}}, ConsistentRead=True,
    )
    le_ids = {item["sk"]["S"] for item in le["Items"]}
    assert le_ids == {"item1"}, f"'score <= 10' with a correctly-typed N operand matched {le_ids!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
