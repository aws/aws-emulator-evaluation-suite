"""create-table-keys-only-gsi-with-non-key-attributes-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-keys-only-gsi-with-non-key-attributes-rejected"
GROUP = "gsi"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _safe_delete_table(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable refuses a GSI whose Projection is KEYS_ONLY but names NonKeyAttributes, with
    the exact ValidationException message, and creates no table; a KEYS_ONLY GSI with no
    NonKeyAttributes is accepted.
    """
    ddb = ctx.client("dynamodb")

    rejected_name = ctx.unique_name("sim2real-behav-ddb-gsikonk-")
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, rejected_name))
    code, message = _error(lambda: ddb.create_table(
        TableName=rejected_name,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "gsipk", "AttributeType": "S"},
        ],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        GlobalSecondaryIndexes=[{
            "IndexName": "gsi1",
            "KeySchema": [{"AttributeName": "gsipk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "KEYS_ONLY", "NonKeyAttributes": ["extra"]},
        }],
        BillingMode="PAY_PER_REQUEST",
    ))
    assert code == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code!r}: {message!r}"
    expected = (
        "One or more parameter values were invalid: ProjectionType is KEYS_ONLY, but "
        "NonKeyAttributes is specified"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, not_found_message = _error(lambda: ddb.describe_table(TableName=rejected_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"a refused CreateTable must create nothing, but DescribeTable gave {not_found_code!r}"
    )
    expected_not_found = f"Requested resource not found: Table: {rejected_name} not found"
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )

    control_name = ctx.unique_name("sim2real-behav-ddb-gsikonk-ok-")
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, control_name))
    ddb.create_table(
        TableName=control_name,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "gsipk", "AttributeType": "S"},
        ],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        GlobalSecondaryIndexes=[{
            "IndexName": "gsi1",
            "KeySchema": [{"AttributeName": "gsipk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "KEYS_ONLY"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.get_waiter("table_exists").wait(TableName=control_name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    control = ddb.describe_table(TableName=control_name)["Table"]
    assert control["TableStatus"] == "ACTIVE", (
        f"positive control: a KEYS_ONLY GSI with no NonKeyAttributes must be accepted, got "
        f"TableStatus={control['TableStatus']!r}"
    )
    control_projection = control["GlobalSecondaryIndexes"][0]["Projection"]
    assert control_projection == {"ProjectionType": "KEYS_ONLY"}, (
        f"expected the accepted GSI's Projection to carry no NonKeyAttributes, got {control_projection!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
