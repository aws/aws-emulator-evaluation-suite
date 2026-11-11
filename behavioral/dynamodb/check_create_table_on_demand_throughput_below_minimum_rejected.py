"""create-table-on-demand-throughput-below-minimum-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-on-demand-throughput-below-minimum-rejected"
GROUP = "table_lifecycle"
SERVICES = ["dynamodb"]

_BELOW_MINIMUM = (
    "ValidationException",
    "One or more parameter values were invalid: Requested MaxReadRequestUnits for "
    "OnDemandThroughput for table is outside of valid range",
)


def expect_error(fn, code: str, message: str) -> None:
    """Calls fn() and asserts it raises exactly (code, message). Raises when fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, f"expected code {code!r}, got {err['Code']!r}"
        assert err["Message"] == message, f"expected message {message!r}, got {err['Message']!r}"
        return
    raise AssertionError(f"expected ({code}, {message!r}); the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable's OnDemandThroughput.MaxReadRequestUnits must be at least 1; a value of 0
    is refused and no table is left behind."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")

    expect_error(
        lambda: ddb.create_table(
            TableName=table,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
            OnDemandThroughput={"MaxReadRequestUnits": 0, "MaxWriteRequestUnits": 5},
        ),
        *_BELOW_MINIMUM,
    )

    # Positive control: the same shape with a valid ceiling succeeds, proving the refusal above
    # was about the value and not the table's other properties.
    ctrl_table = ctx.unique_name("sim2real-behav-ctrl-")
    ddb.create_table(
        TableName=ctrl_table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        OnDemandThroughput={"MaxReadRequestUnits": 1, "MaxWriteRequestUnits": 5},
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=ctrl_table))
    ddb.get_waiter("table_exists").wait(TableName=ctrl_table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    code = None
    try:
        ddb.describe_table(TableName=table)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
    assert code == "ResourceNotFoundException", (
        f"the refused CreateTable must not leave a table behind, DescribeTable gave {code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
