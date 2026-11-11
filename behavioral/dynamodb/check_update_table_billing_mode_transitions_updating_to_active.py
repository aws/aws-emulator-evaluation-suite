"""update-table-billing-mode-transitions-updating-to-active."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-billing-mode-transitions-updating-to-active"
GROUP = 'state-machine'
SERVICES = ['dynamodb']


def _wait_table_active(ddb, table_name, timeout_s=60.0, interval_s=1.0):
    """Poll DescribeTable until TableStatus is ACTIVE (a transient 404 counts as not-yet)."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            status = "PENDING"
        if status == "ACTIVE":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never went ACTIVE in {timeout_s}s (last={status})")


def _force_delete_table(ddb, table_name, timeout_s=300.0, interval_s=2.0):
    """Delete a table; a table already gone is fine.

    A table that is CREATING/UPDATING rejects DeleteTable with ResourceInUseException,
    so that code is retried until it settles or timeout_s passes; anything else raises.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _create_table_and_wait(ddb, ctx, table_name, key_schema, attribute_definitions,
                           billing_mode="PAY_PER_REQUEST", timeout_s=60.0, **kwargs):
    """Create a table, register teardown, and wait until ACTIVE."""
    resp = ddb.create_table(
        TableName=table_name,
        KeySchema=key_schema,
        AttributeDefinitions=attribute_definitions,
        BillingMode=billing_mode,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        **kwargs,
    )
    ctx.on_cleanup(lambda: _force_delete_table(ddb, table_name))
    _wait_table_active(ddb, table_name, timeout_s=timeout_s)
    return resp


def _hash_key_schema(key_name="pk", key_type="S"):
    """Return (KeySchema, AttributeDefinitions) for a hash-only table."""
    return (
        [{"AttributeName": key_name, "KeyType": "HASH"}],
        [{"AttributeName": key_name, "AttributeType": key_type}],
    )


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """UpdateTable starts a billing-mode transition that settles to ACTIVE with the new mode applied.

    This covers the UpdateTable state machine without starting an online GSI backfill (which can
    pin a table in UPDATING for many minutes and cannot be cancelled).
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-billing-")
    key_schema, attr_defs = _hash_key_schema("pk")
    _create_table_and_wait(ddb, ctx, table_name, key_schema, attr_defs)

    before = ddb.describe_table(TableName=table_name)["Table"]
    before_mode = before["BillingModeSummary"]["BillingMode"]
    assert before_mode == "PAY_PER_REQUEST", (
        f"expected freshly-created table billing mode PAY_PER_REQUEST, got {before_mode!r}"
    )

    resp = ddb.update_table(
        TableName=table_name,
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 3, "WriteCapacityUnits": 4},
    )
    start_status = resp["TableDescription"]["TableStatus"]
    assert start_status == "UPDATING", f"expected UPDATING, got {start_status}"

    _wait_table_active(ddb, table_name, timeout_s=600)

    after = ddb.describe_table(TableName=table_name)["Table"]
    after_mode = after["BillingModeSummary"]["BillingMode"]
    assert after_mode == "PROVISIONED", (
        f"expected settled billing mode PROVISIONED, got {after_mode!r}"
    )
    read_cap = after["ProvisionedThroughput"]["ReadCapacityUnits"]
    assert read_cap == 3, f"expected ReadCapacityUnits 3 to persist, got {read_cap}"
    write_cap = after["ProvisionedThroughput"]["WriteCapacityUnits"]
    assert write_cap == 4, f"expected WriteCapacityUnits 4 to persist, got {write_cap}"

    # The data plane must remain fully usable after the billing-mode transition.
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "k1"}, "v": {"S": "post-update"}})
    got = ddb.get_item(TableName=table_name, Key={"pk": {"S": "k1"}}, ConsistentRead=True)["Item"]
    got_v = got["v"]["S"]
    assert got_v == "post-update", (
        f"expected post-transition GetItem to read back 'post-update', got {got_v!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
