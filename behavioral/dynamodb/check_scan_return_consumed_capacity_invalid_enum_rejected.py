"""scan-return-consumed-capacity-invalid-enum-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-return-consumed-capacity-invalid-enum-rejected"
GROUP = "capacity"
SERVICES = ["dynamodb"]
_VALIDATION = (
    "ValidationException",
    "1 validation error detected: Value 'BOGUS' at 'returnConsumedCapacity' failed to satisfy "
    "constraint: Member must satisfy enum value set: [INDEXES, TOTAL, NONE]",
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got = _error(fn)
    assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An out-of-enum ReturnConsumedCapacity on Scan is ValidationException naming the member and
    echoing the value, and the table is still fully scannable with a well-formed call.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-rccenum-scan-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={"pk": {"S": "control"}, "data": {"S": "v"}})

    expect_error(
        lambda: ddb.scan(TableName=table, ReturnConsumedCapacity="BOGUS"),
        *_VALIDATION,
    )

    control = ddb.scan(TableName=table, ReturnConsumedCapacity="TOTAL", ConsistentRead=True)
    assert control["Count"] == 1, f"the rejected Scan must leave the table scannable, got Count={control['Count']}"
    assert control["Items"] == [{"pk": {"S": "control"}, "data": {"S": "v"}}], (
        f"the rejected Scan must leave the item untouched, read back {control['Items']!r}"
    )
    assert set(control["ConsumedCapacity"]) == {"TableName", "CapacityUnits"}, (
        f"ReturnConsumedCapacity=TOTAL must report table-level capacity only, got {control['ConsumedCapacity']!r}"
    )
    assert control["ConsumedCapacity"]["TableName"] == table, (
        f"the reported capacity must name the scanned table, got {control['ConsumedCapacity']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
