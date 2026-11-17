"""scan-filter-expression-between-mixed-type-bounds-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-expression-between-mixed-type-bounds-rejected"
GROUP = "expressions"
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
    """A Scan FilterExpression's BETWEEN with bounds of two different types is
    ValidationException before any item is examined, while same-typed bounds still select.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbbetw-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={"pk": {"S": "i1"}, "score": {"N": "15"}})

    def scan_ids(**kwargs) -> list:
        resp = ddb.scan(TableName=table, ConsistentRead=True, **kwargs)
        return sorted(item["pk"]["S"] for item in resp["Items"])

    # Positive control: matching-typed bounds parse and select the item inside [10, 25].
    ok = scan_ids(
        FilterExpression="score BETWEEN :lo AND :hi",
        ExpressionAttributeValues={":lo": {"N": "10"}, ":hi": {"N": "25"}},
    )
    assert ok == ["i1"], f"the same-type-bounds control returned {ok!r}, expected ['i1']"

    code, message = _error(lambda: ddb.scan(
        TableName=table, ConsistentRead=True,
        FilterExpression="score BETWEEN :lo AND :hi",
        ExpressionAttributeValues={":lo": {"N": "10"}, ":hi": {"S": "25"}},
    ))
    assert code == ERR_VALIDATION, f"the mixed-type-bounds Scan was refused with {code!r}, expected {ERR_VALIDATION!r}"
    expected_message = (
        "Invalid FilterExpression: The BETWEEN operator requires same data type for lower and "
        "upper bounds; lower bound operand: AttributeValue: {N:10}, upper bound operand: "
        "AttributeValue: {S:25}"
    )
    assert message == expected_message, f"unexpected message for the mixed-type BETWEEN: {message!r}"

    # After the rejection the table still answers the control exactly as before.
    again = scan_ids(
        FilterExpression="score BETWEEN :lo AND :hi",
        ExpressionAttributeValues={":lo": {"N": "10"}, ":hi": {"N": "25"}},
    )
    assert again == ["i1"], f"after the rejection the control returned {again!r}, expected ['i1']"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
