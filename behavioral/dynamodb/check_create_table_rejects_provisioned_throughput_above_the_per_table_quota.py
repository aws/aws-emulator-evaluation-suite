"""create-table-rejects-provisioned-throughput-above-the-per-table-quota."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-rejects-provisioned-throughput-above-the-per-table-quota"
GROUP = "limits"
SERVICES = ["dynamodb"]


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success fails too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        actual_code, actual_message = err.get("Code"), err.get("Message")
        assert actual_code == code, f"expected error code {code!r}, got {actual_code!r}"
        assert actual_message == message, f"expected message {message!r}, got {actual_message!r}"
        return
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _wait_active(ddb, table_name, timeout_s=300.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _teardown_table(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable refuses a ReadCapacityUnits or WriteCapacityUnits one above the per-table
    ceiling DescribeLimits reports, with LimitExceededException and no table created; a
    request within the ceiling succeeds."""
    ddb = ctx.client("dynamodb")
    attribute_definitions = [{"AttributeName": "pk", "AttributeType": "S"}]
    key_schema = [{"AttributeName": "pk", "KeyType": "HASH"}]

    limits = ddb.describe_limits()
    table_max_read = limits["TableMaxReadCapacityUnits"]
    table_max_write = limits["TableMaxWriteCapacityUnits"]

    over_read = table_max_read + 1
    t_read = ctx.unique_name("sim2real-behav-ddb-qr-")
    _READ_OVER = (
        "LimitExceededException",
        f"The requested ReadCapacityUnits, {over_read}, is above the per table maximum for "
        f"the account in {ctx.region}. Per table maximum: {table_max_read}. Refer to the "
        "Amazon DynamoDB Developer Guide for current limits and how to request higher limits.",
    )
    expect_error(
        lambda: ddb.create_table(
            TableName=t_read,
            AttributeDefinitions=attribute_definitions,
            KeySchema=key_schema,
            BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": over_read, "WriteCapacityUnits": 1},
        ),
        *_READ_OVER,
    )
    _READ_NOT_FOUND = (
        "ResourceNotFoundException",
        f"Requested resource not found: Table: {t_read} not found",
    )
    expect_error(lambda: ddb.describe_table(TableName=t_read), *_READ_NOT_FOUND)

    over_write = table_max_write + 1
    t_write = ctx.unique_name("sim2real-behav-ddb-qw-")
    _WRITE_OVER = (
        "LimitExceededException",
        f"The requested WriteCapacityUnits, {over_write}, is above the per table maximum for "
        f"the account in {ctx.region}. Per table maximum: {table_max_write}. Refer to the "
        "Amazon DynamoDB Developer Guide for current limits and how to request higher limits.",
    )
    expect_error(
        lambda: ddb.create_table(
            TableName=t_write,
            AttributeDefinitions=attribute_definitions,
            KeySchema=key_schema,
            BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": over_write},
        ),
        *_WRITE_OVER,
    )
    _WRITE_NOT_FOUND = (
        "ResourceNotFoundException",
        f"Requested resource not found: Table: {t_write} not found",
    )
    expect_error(lambda: ddb.describe_table(TableName=t_write), *_WRITE_NOT_FOUND)

    over_read_both = table_max_read + 2
    over_write_both = table_max_write + 2
    t_both = ctx.unique_name("sim2real-behav-ddb-qb-")
    _BOTH_OVER = (
        "LimitExceededException",
        f"The requested ReadCapacityUnits, {over_read_both}, is above the per table maximum "
        f"for the account in {ctx.region}. Per table maximum: {table_max_read}. Refer to the "
        "Amazon DynamoDB Developer Guide for current limits and how to request higher limits.",
    )
    expect_error(
        lambda: ddb.create_table(
            TableName=t_both,
            AttributeDefinitions=attribute_definitions,
            KeySchema=key_schema,
            BillingMode="PROVISIONED",
            ProvisionedThroughput={
                "ReadCapacityUnits": over_read_both,
                "WriteCapacityUnits": over_write_both,
            },
        ),
        *_BOTH_OVER,
    )
    _BOTH_NOT_FOUND = (
        "ResourceNotFoundException",
        f"Requested resource not found: Table: {t_both} not found",
    )
    expect_error(lambda: ddb.describe_table(TableName=t_both), *_BOTH_NOT_FOUND)

    t_ok = ctx.unique_name("sim2real-behav-ddb-qok-")
    ddb.create_table(
        TableName=t_ok,
        AttributeDefinitions=attribute_definitions,
        KeySchema=key_schema,
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_table(ddb, t_ok))
    desc = _wait_active(ddb, t_ok)
    assert desc["ProvisionedThroughput"]["ReadCapacityUnits"] == 5, (
        f"expected ReadCapacityUnits 5, got {desc['ProvisionedThroughput']['ReadCapacityUnits']!r}"
    )
    assert desc["ProvisionedThroughput"]["WriteCapacityUnits"] == 5, (
        f"expected WriteCapacityUnits 5, got {desc['ProvisionedThroughput']['WriteCapacityUnits']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
