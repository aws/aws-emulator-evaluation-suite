"""describe-continuous-backups-deleted-table-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-continuous-backups-deleted-table-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeContinuousBackups on a live table reports ContinuousBackupsStatus ENABLED; the
    identical call on that table's name after DeleteTable raises TableNotFoundException with the
    exact message.
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-dcb-")

    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _wait_table_active(ddb, table_name)

    # Positive control: DescribeContinuousBackups on the live table succeeds and reports the
    # continuous-backups machinery as enabled. Without this, a target that returns
    # TableNotFoundException for every DescribeContinuousBackups call would pass the negative
    # below too.
    described = _wait_continuous_backups_enabled(ddb, table_name)
    assert described["ContinuousBackupsStatus"] == "ENABLED", described

    ddb.delete_table(TableName=table_name)
    _wait_table_gone(ddb, table_name)

    # The identical call on the now-deleted table name is rejected, not answered with a stale or
    # empty description.
    code, message = _error(lambda: ddb.describe_continuous_backups(TableName=table_name))
    assert code == "TableNotFoundException", f"expected TableNotFoundException, got {code}"
    expected = f"Table not found: {table_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # A table name that never existed at all is rejected the identical way.
    never_existed = ctx.unique_name("sim2real-behav-dcb-never-")
    never_code, never_message = _error(lambda: ddb.describe_continuous_backups(TableName=never_existed))
    assert never_code == "TableNotFoundException", f"expected TableNotFoundException, got {never_code}"
    expected_never = f"Table not found: {never_existed}"
    assert never_message == expected_never, f"expected message {expected_never!r}, got {never_message!r}"


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An accepted call raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _wait_table_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} did not become ACTIVE within {timeout_s}s")


def _wait_continuous_backups_enabled(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_continuous_backups(TableName=table_name)["ContinuousBackupsDescription"]
        if desc["ContinuousBackupsStatus"] == "ENABLED":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"continuous backups for {table_name} never became ENABLED")


def _wait_table_gone(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ddb.describe_table(TableName=table_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} was never deleted within {timeout_s}s")


def _safe_delete_table(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
