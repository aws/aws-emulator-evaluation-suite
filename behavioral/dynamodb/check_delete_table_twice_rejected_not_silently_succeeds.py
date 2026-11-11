"""delete-table-twice-rejected-not-silently-succeeds."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-table-twice-rejected-not-silently-succeeds"
GROUP = "overly-permissive"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second DeleteTable call issued after the table has fully disappeared
    returns ResourceNotFoundException, rather than succeeding silently a
    second time or returning some other generic error."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-")
    table_kwargs = dict(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ddb.create_table(**table_kwargs)
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _wait_table_active(ddb, table_name)

    # First delete: must succeed.
    ddb.delete_table(TableName=table_name)
    _wait_table_gone(ddb, table_name)

    # Second delete on the now fully-deleted table: must be rejected, not a
    # silent no-op success and not some unrelated error.
    code, message = _error(lambda: ddb.delete_table(TableName=table_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on second DeleteTable, got {code!r}"
    )
    expected_message = f"Requested resource not found: Table: {table_name} not found"
    assert message == expected_message, (
        f"expected the second DeleteTable message {expected_message!r}, got {message!r}"
    )

    # DescribeTable on the same name must agree the table is gone.
    describe_code, describe_message = _error(lambda: ddb.describe_table(TableName=table_name))
    assert describe_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on DescribeTable of a deleted table, got {describe_code!r}"
    )
    expected_describe = f"Requested resource not found: Table: {table_name} not found"
    assert describe_message == expected_describe, (
        f"expected the DescribeTable message {expected_describe!r}, got {describe_message!r}"
    )

    # The name is now free: recreating with the identical name must succeed and
    # become usable, proving the deletion actually released the identifier
    # rather than leaving the target in a phantom not-found-but-still-reserved
    # state.
    ddb.create_table(**table_kwargs)
    recreated = _wait_table_active(ddb, table_name)
    assert recreated["TableName"] == table_name, (
        f"expected recreated table name {table_name!r}, got {recreated.get('TableName')!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _wait_table_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _wait_table_gone(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ddb.describe_table(TableName=table_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never became fully deleted")


def _safe_delete_table(ddb, table_name):
    from botocore.exceptions import ClientError

    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
