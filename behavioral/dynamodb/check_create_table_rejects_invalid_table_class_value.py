"""create-table-rejects-invalid-table-class-value."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-rejects-invalid-table-class-value"
GROUP = "table_lifecycle"
SERVICES = ["dynamodb"]

_INVALID_TABLE_CLASS = (
    "ValidationException",
    "Invalid table-class parameter provided. Please try again with a valid table-class "
    "value: [STANDARD, STANDARD_INFREQUENT_ACCESS].",
)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _code(fn) -> str:
    """The Error.Code ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable rejects a TableClass value outside the enum with the exact AWS message,
    creating no table, while a valid TableClass on the same call shape still succeeds.
    """
    ddb = ctx.client("dynamodb")
    rejected = ctx.unique_name("sim2real-behav-")

    expect_error(
        lambda: ddb.create_table(
            TableName=rejected,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
            TableClass="FREQUENT_ACCESS",
        ),
        *_INVALID_TABLE_CLASS,
    )
    code = _code(lambda: ddb.describe_table(TableName=rejected))
    assert code == "ResourceNotFoundException", (
        f"the rejected CreateTable must not have created a table, "
        f"DescribeTable gave {code!r} instead of ResourceNotFoundException"
    )

    accepted = ctx.unique_name("sim2real-behav-")
    created = ddb.create_table(
        TableName=accepted,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        TableClass="STANDARD",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=accepted))
    ddb.get_waiter("table_exists").wait(
        TableName=accepted, WaiterConfig={"Delay": 2, "MaxAttempts": 250}
    )
    assert created["TableDescription"].get("TableClassSummary") == {"TableClass": "STANDARD"}, (
        f"a valid TableClass on the same call shape must still succeed and be reported, "
        f"got {created['TableDescription'].get('TableClassSummary')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
