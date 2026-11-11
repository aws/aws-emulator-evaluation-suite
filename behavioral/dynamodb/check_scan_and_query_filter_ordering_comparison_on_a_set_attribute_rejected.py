"""scan-and-query-filter-ordering-comparison-on-a-set-attribute-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-and-query-filter-ordering-comparison-on-a-set-attribute-rejected"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_OPERAND_TYPE_MSG = (
    "Invalid FilterExpression: Incorrect operand type for operator or function; "
    "operator or function: {op}, operand type: {op_type}"
)

_SET_OPERANDS = {
    "ssattr": ("SS", {"SS": ["a", "b"]}),
    "nsattr": ("NS", {"NS": ["1", "2"]}),
    "bsattr": ("BS", {"BS": [b"x", b"y"]}),
}
_ORDERING_OPS = ["<", ">"]


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; raises if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan or Query FilterExpression's '<' and '>' refuse an SS, NS or BS operand with
    ValidationException, and leave the item exactly as it was before the rejected calls.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-setord-")
    ddb.create_table(
        TableName=table,
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
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    pk = "p1"
    item = {
        "pk": {"S": pk}, "sk": {"S": "item1"},
        "ssattr": {"SS": ["a", "b"]}, "nsattr": {"NS": ["1", "2"]}, "bsattr": {"BS": [b"x", b"y"]},
    }
    ddb.put_item(TableName=table, Item=item)

    for attr, (op_type, operand) in _SET_OPERANDS.items():
        for op in _ORDERING_OPS:
            code, message = _error(lambda: ddb.scan(
                TableName=table,
                FilterExpression=f"{attr} {op} :v",
                ExpressionAttributeValues={":v": operand},
                ConsistentRead=True,
            ))
            assert code == "ValidationException", (
                f"Scan '{attr} {op} :v' with a {op_type} operand answered {code!r}, expected "
                f"ValidationException"
            )
            expected_message = _OPERAND_TYPE_MSG.format(op=op, op_type=op_type)
            assert message == expected_message, (
                f"Scan '{attr} {op} :v' with a {op_type} operand said {message!r}, expected "
                f"{expected_message!r}"
            )

    # The same refusal applies to Query's FilterExpression, applied after the key condition.
    code, message = _error(lambda: ddb.query(
        TableName=table,
        KeyConditionExpression="pk = :pk",
        FilterExpression="ssattr < :v",
        ExpressionAttributeValues={":pk": {"S": pk}, ":v": {"SS": ["a", "b"]}},
        ConsistentRead=True,
    ))
    assert code == "ValidationException", (
        f"Query 'ssattr < :v' with an SS operand answered {code!r}, expected ValidationException"
    )
    expected_message = _OPERAND_TYPE_MSG.format(op="<", op_type="SS")
    assert message == expected_message, (
        f"Query 'ssattr < :v' with an SS operand said {message!r}, expected {expected_message!r}"
    )

    # Positive control: the rejected calls wrote nothing, and the item reads back unchanged.
    after = ddb.get_item(TableName=table, Key={"pk": {"S": pk}, "sk": {"S": "item1"}}, ConsistentRead=True)["Item"]
    assert after == item, f"the item changed after the rejected filter calls, got {after!r}, expected {item!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
