"""delete-item-nonexistent-key-is-noop."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-nonexistent-key-is-noop"
GROUP = 'item_crud'
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


def _create_table_and_wait(ddb, ctx, table_name, key_schema, attribute_definitions,
                           billing_mode="PAY_PER_REQUEST", timeout_s=60.0, **kwargs):
    """Create a table, register teardown, and wait until ACTIVE."""
    resp = ddb.create_table(
        TableName=table_name,
        KeySchema=key_schema,
        AttributeDefinitions=attribute_definitions,
        BillingMode=billing_mode,
        Tags=[{"Key": "sim2real", "Value": "delete-item-nonexistent-key-is-noop"}],
        **kwargs,
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ddb, table_name, timeout_s=timeout_s)
    return resp


def _hash_key_schema(key_name="pk", key_type="S"):
    """Return (KeySchema, AttributeDefinitions) for a hash-only table."""
    return (
        [{"AttributeName": key_name, "KeyType": "HASH"}],
        [{"AttributeName": key_name, "AttributeType": key_type}],
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteItem on a key that was never written succeeds silently (no error, no Attributes),
    the key stays absent under an independent read, and an unrelated item in the same table is
    left untouched (the no-op is scoped to the addressed key, not a side effect on the table)."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-delnoop-")
    key_schema, attr_defs = _hash_key_schema("pk")
    _create_table_and_wait(ddb, ctx, table_name, key_schema, attr_defs)

    control_key = {"pk": {"S": "control-survives"}}
    ddb.put_item(TableName=table_name, Item={**control_key, "data": {"S": "untouched"}})

    missing_key = {"pk": {"S": "never-existed"}}
    resp = ddb.delete_item(
        TableName=table_name,
        Key=missing_key,
        ReturnValues="ALL_OLD",
    )
    assert "Attributes" not in resp or not resp["Attributes"], (
        f"expected no Attributes deleting a key that was never written, got {resp.get('Attributes')!r}"
    )

    # independent read at the destination: the addressed key stayed absent
    got = ddb.get_item(TableName=table_name, Key=missing_key, ConsistentRead=True)
    assert "Item" not in got, f"delete of a never-written key conjured an item: {got.get('Item')!r}"

    # the no-op must be scoped to the addressed key: an unrelated item survives untouched
    control = ddb.get_item(TableName=table_name, Key=control_key, ConsistentRead=True)
    assert control.get("Item", {}).get("data") == {"S": "untouched"}, (
        f"expected unrelated item to survive untouched, got {control.get('Item')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
