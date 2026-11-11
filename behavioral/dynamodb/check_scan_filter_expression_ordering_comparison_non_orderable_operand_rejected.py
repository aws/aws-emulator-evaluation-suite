"""scan-filter-expression-ordering-comparison-non-orderable-operand-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-expression-ordering-comparison-non-orderable-operand-rejected"
GROUP = "scan"
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
    """A Scan FilterExpression's <= and >= refuse a BOOL or NULL operand with ValidationException,
    and leave the table's content exactly as scanned before the rejected calls.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-scanord-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={"id": {"S": "item1"}, "score": {"N": "10"}})
    ddb.put_item(TableName=table, Item={"id": {"S": "item2"}, "score": {"N": "20"}})

    def _scan_compare(op, operand_value):
        return ddb.scan(
            TableName=table,
            FilterExpression=f"score {op} :v",
            ExpressionAttributeValues={":v": operand_value},
            ConsistentRead=True,
        )

    for op in ("<=", ">="):
        for op_type, operand in _NON_ORDERABLE.items():
            code, message = _error(lambda: _scan_compare(op, operand))
            assert code == "ValidationException", (
                f"'score {op} :v' with a {op_type} operand answered {code!r}, expected "
                f"ValidationException"
            )
            expected_message = _OPERAND_TYPE_MSG.format(op=op, op_type=op_type)
            assert message == expected_message, (
                f"'score {op} :v' with a {op_type} operand said {message!r}, expected "
                f"{expected_message!r}"
            )

    unfiltered = ddb.scan(TableName=table, ConsistentRead=True)
    assert unfiltered["Count"] == 2, (
        f"after the rejected comparisons the table held {unfiltered['Count']} item(s), expected 2: "
        f"the rejected reads must not have written or removed anything"
    )

    # Positive control: the same operators over a correctly-typed N operand still filter normally.
    le = ddb.scan(TableName=table, FilterExpression="score <= :v",
                  ExpressionAttributeValues={":v": {"N": "10"}}, ConsistentRead=True)
    le_ids = {item["id"]["S"] for item in le["Items"]}
    assert le_ids == {"item1"}, f"'score <= 10' with a correctly-typed N operand matched {le_ids!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
