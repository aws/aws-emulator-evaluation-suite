"""update-table-rejected-while-a-prior-throughput-change-is-still-applying."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-rejected-while-a-prior-throughput-change-is-still-applying"
GROUP = "table_lifecycle"
SERVICES = ["dynamodb"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(ddb, table: str, predicate, *, timeout_s: float, description: str) -> dict:
    """Poll DescribeTable every 2 s for ``table`` until ``predicate(table_desc)`` holds."""
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if predicate(desc):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} never reached {description}; last {desc!r}")


def _delete_once_active(ddb, table: str) -> None:
    """Wait out any in-flight UPDATING before DeleteTable, so a mid-check failure still cleans up."""
    _poll_until(ddb, table, lambda d: d["TableStatus"] == "ACTIVE", timeout_s=280, description="ACTIVE")
    ddb.delete_table(TableName=table)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second UpdateTable sent right after an accepted throughput change is refused with
    ResourceInUseException, and the first change still settles at the capacity it asked for.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-updating-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
    )
    ctx.on_cleanup(lambda: _delete_once_active(ddb, table))
    _poll_until(ddb, table, lambda d: d["TableStatus"] == "ACTIVE", timeout_s=280, description="ACTIVE")

    first = ddb.update_table(
        TableName=table, ProvisionedThroughput={"ReadCapacityUnits": 3, "WriteCapacityUnits": 3}
    )["TableDescription"]
    assert first["TableStatus"] == "UPDATING", (
        f"the accepted UpdateTable must describe the table as UPDATING, got {first['TableStatus']!r}"
    )

    # Sent right away, with no wait, while the first change is still being applied.
    code, message = _error(lambda: ddb.update_table(
        TableName=table, ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
    ))
    want = (
        "ResourceInUseException",
        "Attempt to change a resource which is still in use: Table IOPS are currently being "
        f"updated. Table: {table}",
    )
    assert (code, message) == want, (
        f"a second UpdateTable while the first was UPDATING gave {code!r}: {message!r}, expected {want!r}"
    )

    # The in-flight change settles at exactly 3/3; the poll times out (and fails) otherwise.
    _poll_until(
        ddb, table,
        lambda d: d["TableStatus"] == "ACTIVE"
        and (d["ProvisionedThroughput"].get("ReadCapacityUnits"),
             d["ProvisionedThroughput"].get("WriteCapacityUnits")) == (3, 3),
        timeout_s=280, description="ACTIVE at 3 read / 3 write",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
