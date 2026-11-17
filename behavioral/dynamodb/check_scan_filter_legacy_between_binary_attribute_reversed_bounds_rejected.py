"""scan-filter-legacy-between-binary-attribute-reversed-bounds-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "scan-filter-legacy-between-binary-attribute-reversed-bounds-rejected"
GROUP = "scan"
SERVICES = ["dynamodb"]

_LO, _HI = b"\x01", b"\x80"

_REJECTED = (
    "ValidationException",
    "One or more parameter values were invalid: The BETWEEN condition was provided a range "
    "where the lower bound is greater than the upper bound",
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
    """A legacy ScanFilter BETWEEN on a Binary attribute whose lower bound is greater than its
    upper bound under unsigned byte order is rejected with ValidationException; the ordered
    bounds still match.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-ddbscblr-")
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
        TableName=table, ScanFilter={
            "bin": {"ComparisonOperator": "BETWEEN", "AttributeValueList": [{"B": _HI}, {"B": _LO}]}
        },
    ))
    assert got == _REJECTED, (
        f"legacy ScanFilter BETWEEN with bounds {_HI!r},{_LO!r} returned {got!r}, expected "
        f"{_REJECTED!r}"
    )

    # Positive control: the same table, same attribute, bounds the right way round, succeeds.
    ok = ddb.scan(TableName=table, ConsistentRead=True, ScanFilter={
        "bin": {"ComparisonOperator": "BETWEEN", "AttributeValueList": [{"B": _LO}, {"B": _HI}]}
    })
    ids = sorted(i["id"]["S"] for i in ok["Items"])
    assert ids == ["item1"], f"the correctly ordered BETWEEN returned {ids!r}, expected ['item1']"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
