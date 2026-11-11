"""scan-filter-between-binary-attribute-reversed-bounds-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "scan-filter-between-binary-attribute-reversed-bounds-rejected"
GROUP = "data-plane"
SERVICES = ["dynamodb"]

_LO, _HI = b"\x01", b"\x80"

_REJECTED = (
    "ValidationException",
    "Invalid FilterExpression: The BETWEEN operator requires upper bound to be greater than or "
    "equal to lower bound; lower bound operand: AttributeValue: {B:gA==}, upper bound operand: "
    "AttributeValue: {B:AQ==}",
)


def _error_code_and_message(fn) -> tuple:
    """The (Code, Message) `fn` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression BETWEEN on a Binary attribute with the bounds swapped is
    rejected with the exact bytes of both operands, read as unsigned values.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-ddbscbr-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={"id": {"S": "item1"}, "bin": {"B": _LO}})

    got = _error_code_and_message(lambda: ddb.scan(
        TableName=table, FilterExpression="bin BETWEEN :hi AND :lo",
        ExpressionAttributeValues={":hi": {"B": _HI}, ":lo": {"B": _LO}},
    ))
    assert got == _REJECTED, f"reversed BETWEEN bounds {_HI!r},{_LO!r} returned {got!r}, expected {_REJECTED!r}"

    # Positive control: the same table, same attribute, bounds the right way round, succeeds.
    ok = ddb.scan(TableName=table, ConsistentRead=True,
                  FilterExpression="bin BETWEEN :lo AND :hi",
                  ExpressionAttributeValues={":lo": {"B": _LO}, ":hi": {"B": _HI}})
    ids = sorted(i["id"]["S"] for i in ok["Items"])
    assert ids == ["item1"], f"the correctly ordered BETWEEN returned {ids!r}, expected ['item1']"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
