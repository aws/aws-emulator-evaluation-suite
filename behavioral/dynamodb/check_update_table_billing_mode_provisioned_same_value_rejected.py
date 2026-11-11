"""update-table-billing-mode-provisioned-same-value-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-billing-mode-provisioned-same-value-rejected"
GROUP = "table_lifecycle"
SERVICES = ["dynamodb"]

_SAME_VALUE_NO_OP = (
    "ValidationException",
    "The provisioned throughput for the table will not change. The requested value equals the "
    "current value. Current ReadCapacityUnits provisioned for the table: 1. Requested "
    "ReadCapacityUnits: 1. Current WriteCapacityUnits provisioned for the table: 1. Requested "
    "WriteCapacityUnits: 1. Refer to the Amazon DynamoDB Developer Guide for current limits and "
    "how to request higher limits.",
)


def _wait_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    """Poll DescribeTable until TableStatus is ACTIVE."""
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never settled to ACTIVE in {timeout_s}s (last={desc!r})")


def _wait_capacity(ddb, table_name, target, timeout_s=120.0, interval_s=2.0):
    """Poll until TableStatus is ACTIVE and ProvisionedThroughput equals ``target``."""
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        cap = desc["ProvisionedThroughput"]
        got = (cap["ReadCapacityUnits"], cap["WriteCapacityUnits"])
        if desc["TableStatus"] == "ACTIVE" and got == target:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never reached {target!r} in {timeout_s}s (last={desc!r})")


def expect_error(fn, code, message):
    """Assert ``fn`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTable rejects a PROVISIONED table's same-value throughput as a no-op, whether or not
    BillingMode=PROVISIONED is also given, and a genuine capacity change still applies afterward.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-provnoop-")
    key_schema = [{"AttributeName": "pk", "KeyType": "HASH"}]
    attr_defs = [{"AttributeName": "pk", "AttributeType": "S"}]

    ddb.create_table(
        TableName=table, KeySchema=key_schema, AttributeDefinitions=attr_defs,
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_active(ddb, table)

    expect_error(
        lambda: ddb.update_table(
            TableName=table, BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        ),
        *_SAME_VALUE_NO_OP,
    )
    expect_error(
        lambda: ddb.update_table(
            TableName=table,
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        ),
        *_SAME_VALUE_NO_OP,
    )

    desc = ddb.describe_table(TableName=table)["Table"]
    status = desc["TableStatus"]
    assert status == "ACTIVE", f"expected the rejected no-op to leave the table ACTIVE, got {status!r}"
    cap = desc["ProvisionedThroughput"]
    got_cap = (cap["ReadCapacityUnits"], cap["WriteCapacityUnits"])
    assert got_cap == (1, 1), f"expected throughput to stay (1, 1) after the rejections, got {got_cap!r}"

    ddb.update_table(TableName=table, ProvisionedThroughput={"ReadCapacityUnits": 2, "WriteCapacityUnits": 1})
    after = _wait_capacity(ddb, table, (2, 1))
    after_cap = after["ProvisionedThroughput"]
    got_after = (after_cap["ReadCapacityUnits"], after_cap["WriteCapacityUnits"])
    assert got_after == (2, 1), f"expected a genuine capacity change to (2, 1) to apply, got {got_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
