"""put-item-overwrite-replaces-item."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-overwrite-replaces-item"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem fully replaces an existing item (no merge) — previously-present attributes disappear."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-overwrite-")
    key_schema, attr_defs = _hash_key_schema("pk")
    _create_table_and_wait(ddb, ctx, table_name, key_schema, attr_defs)

    ddb.put_item(TableName=table_name, Item={"pk": {"S": "k1"}, "a": {"N": "1"}, "b": {"N": "2"}})

    resp = ddb.put_item(
        TableName=table_name,
        Item={"pk": {"S": "k1"}, "c": {"N": "3"}},
        ReturnValues="ALL_OLD",
    )
    old_attrs = resp["Attributes"]
    assert old_attrs["a"]["N"] == "1", f"expected old attribute a=1, got {old_attrs.get('a')}"
    assert old_attrs["b"]["N"] == "2", f"expected old attribute b=2, got {old_attrs.get('b')}"

    item = ddb.get_item(TableName=table_name, Key={"pk": {"S": "k1"}}, ConsistentRead=True)["Item"]
    assert "a" not in item, f"expected attribute a to be gone after overwrite, item={item}"
    assert "b" not in item, f"expected attribute b to be gone after overwrite, item={item}"
    assert item["c"]["N"] == "3", f"expected surviving attribute c=3, got {item.get('c')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
