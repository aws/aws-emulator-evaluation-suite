"""gsi-creating-blocks-delete-table."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-creating-blocks-delete-table"
GROUP = "gsi"
SERVICES = ["dynamodb"]


def _poll_until(
    probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _teardown(undo, *not_found):
    """A cleanup running ``undo()`` that returns only on the resource's own not-found codes."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error_detail(fn):
    """The (code, message) a rejected call returned; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, the call succeeded: {result!r}")


def _wait_table_active(ddb, name, timeout_s=90):
    return _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"],
        lambda t: (
            t["TableStatus"] == "ACTIVE"
            and all(
                idx.get("IndexStatus", "ACTIVE") == "ACTIVE"
                for idx in t.get("GlobalSecondaryIndexes", [])
            )
        ),
        timeout_s=timeout_s,
        interval_s=1.0,
        description=f"table {name} ACTIVE",
    )


def _wait_table_deleted(ddb, name, timeout_s=90):
    def probe():
        try:
            return ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return "GONE"
            raise

    _poll_until(
        probe,
        lambda s: s == "GONE",
        timeout_s=timeout_s,
        interval_s=1.0,
        description=f"table {name} deleted",
    )


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTable while a GSI added with UpdateTable is still CREATING raises ResourceInUseException with the exact
    message and leaves the table; once the GSI is ACTIVE, DeleteTable removes the table.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=t), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={"pk": {"S": "a"}, "gsi_pk": {"S": "grp"}})

    ddb.update_table(
        TableName=t,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "gsi_pk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexUpdates=[
            {
                "Create": {
                    "IndexName": "late-gsi",
                    "KeySchema": [{"AttributeName": "gsi_pk", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                }
            }
        ],
    )

    # Immediately (no waiting) confirm the GSI is still building, then try to
    # delete the whole table right on top of that in-progress build.
    described = ddb.describe_table(TableName=t)["Table"]
    gsi_status = next(
        g["IndexStatus"]
        for g in described["GlobalSecondaryIndexes"]
        if g["IndexName"] == "late-gsi"
    )
    assert gsi_status == "CREATING", (
        f"expected the newly-requested GSI to still be CREATING, got {gsi_status}"
    )

    code, message = _error_detail(lambda: ddb.delete_table(TableName=t))
    assert code == "ResourceInUseException", (
        f"expected ResourceInUseException, got {code}"
    )
    in_use_message = (
        "Attempt to change a resource which is still in use: Cannot delete table while "
        "indexes are being created, updated, or deleted."
    )
    assert message == in_use_message, f"expected message {in_use_message!r}, got {message!r}"

    # Table must still exist, untouched, after the rejected delete attempt.
    still_active = ddb.describe_table(TableName=t)["Table"]
    assert still_active["TableName"] == t, still_active

    # Once the GSI settles, DeleteTable must succeed normally. Real AWS GSI
    # backfill commonly takes several minutes and can exceed thirteen even for a
    # single-item table, so the wait takes most of the suite's 1800s per-check
    # budget and leaves the rest for the delete that follows.
    _wait_table_active(ddb, t, timeout_s=1500)
    ddb.delete_table(TableName=t)
    _wait_table_deleted(ddb, t)
    gone_code, gone_message = _error_detail(lambda: ddb.describe_table(TableName=t))
    assert gone_code == "ResourceNotFoundException", gone_code
    not_found_message = f"Requested resource not found: Table: {t} not found"
    assert gone_message == not_found_message, (
        f"expected message {not_found_message!r}, got {gone_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
