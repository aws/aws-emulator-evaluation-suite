"""scan-filter-between-operator-rejected-for-bs-and-ns-operands."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-between-operator-rejected-for-bs-and-ns-operands"
GROUP = "scan"
SERVICES = ["dynamodb"]

_OPERAND_TYPE_MSG = (
    "Invalid FilterExpression: Incorrect operand type for operator or function; "
    "operator or function: BETWEEN, operand type: {op_type}"
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; raises if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression's BETWEEN refuses a Binary Set or Number Set operand with
    ValidationException, and leaves the item exactly as it was before the rejected calls.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbbtwn-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    item = {
        "pk": {"S": "item"},
        "bs": {"BS": [b"\x02"]},
        "ns": {"NS": ["5"]},
        "score": {"N": "5"},
    }
    ddb.put_item(TableName=table, Item=item)

    def scan(**kwargs) -> dict:
        return ddb.scan(TableName=table, ConsistentRead=True, **kwargs)

    for attr, op_type, lo, hi in (
        ("bs", "BS", {"BS": [b"\x01"]}, {"BS": [b"\x05"]}),
        ("ns", "NS", {"NS": ["1"]}, {"NS": ["9"]}),
    ):
        code, message = _error(lambda attr=attr, lo=lo, hi=hi: scan(
            FilterExpression=f"{attr} BETWEEN :lo AND :hi",
            ExpressionAttributeValues={":lo": lo, ":hi": hi},
        ))
        assert code == "ValidationException", (
            f"Scan '{attr} BETWEEN :lo AND :hi' with a {op_type} operand answered {code!r}, "
            "expected ValidationException"
        )
        expected_message = _OPERAND_TYPE_MSG.format(op_type=op_type)
        assert message == expected_message, (
            f"Scan '{attr} BETWEEN :lo AND :hi' with a {op_type} operand said {message!r}, "
            f"expected {expected_message!r}"
        )

    # Positive control: BETWEEN over the correctly typed Number attribute still admits the item,
    # proving the rejections above are about the BS/NS operand type, not BETWEEN itself.
    control = scan(
        FilterExpression="score BETWEEN :lo AND :hi",
        ExpressionAttributeValues={":lo": {"N": "1"}, ":hi": {"N": "9"}},
    )
    control_pks = {i["pk"]["S"] for i in control["Items"]}
    assert control_pks == {"item"}, (
        f"score BETWEEN 1 AND 9 selected {sorted(control_pks)!r}, expected ['item']"
    )

    # The rejected calls read nothing and changed nothing: the item is exactly as it was written.
    after = ddb.get_item(TableName=table, Key={"pk": {"S": "item"}}, ConsistentRead=True)["Item"]
    assert after["bs"] == item["bs"] and after["ns"] == item["ns"], (
        f"item changed after the rejected BETWEEN calls: {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
