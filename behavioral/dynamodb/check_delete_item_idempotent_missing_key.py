"""delete-item-idempotent-missing-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-idempotent-missing-key"
GROUP = 'item_crud'
SERVICES = ['dynamodb']


def _wait_for_table_active(ddb, table_name, timeout_s=90.0, interval_s=1.0):
    """Poll DescribeTable until ACTIVE. CreateTable is eventually consistent, so a
    transient ResourceNotFoundException counts as "not yet", never a failure."""
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


def _create_simple_table(ddb, ctx):
    """Create a pk (S) + sk (S) composite-key table, register teardown, wait ACTIVE."""
    table_name = ctx.unique_name("sim2real-behav-ddb-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_for_table_active(ddb, table_name)
    return table_name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteItem with ReturnValues=ALL_OLD on a missing key succeeds with no Attributes and no item, also when
    repeated; on a real item it returns the old payload and removes the item, and a repeat delete is a no-op.
    """
    ddb = ctx.client("dynamodb")
    table_name = _create_simple_table(ddb, ctx)
    missing_key = {"pk": {"S": "missing"}, "sk": {"S": "x"}}

    resp = ddb.delete_item(TableName=table_name, Key=missing_key, ReturnValues="ALL_OLD")
    assert "Attributes" not in resp, f"expected no Attributes deleting a missing key, got {resp}"
    read1 = ddb.get_item(TableName=table_name, Key=missing_key, ConsistentRead=True)
    assert "Item" not in read1, f"expected no item at missing key, got {read1}"

    # calling it again is still a no-op success, independently confirmed absent
    resp2 = ddb.delete_item(TableName=table_name, Key=missing_key, ReturnValues="ALL_OLD")
    assert "Attributes" not in resp2, f"expected no Attributes on repeat delete, got {resp2}"
    read2 = ddb.get_item(TableName=table_name, Key=missing_key, ConsistentRead=True)
    assert "Item" not in read2, f"expected item to remain absent after repeat delete, got {read2}"

    # positive control: prove ReturnValues="ALL_OLD" reports real attributes when something
    # actually existed, so the two "not in resp" assertions above are not vacuous
    real_key = {"pk": {"S": "present"}, "sk": {"S": "y"}}
    ddb.put_item(TableName=table_name, Item={**real_key, "payload": {"S": "hello"}})
    put_read = ddb.get_item(TableName=table_name, Key=real_key, ConsistentRead=True)
    assert "Item" in put_read, f"expected item present after PutItem, got {put_read}"

    del_resp = ddb.delete_item(TableName=table_name, Key=real_key, ReturnValues="ALL_OLD")
    deleted_payload = del_resp.get("Attributes", {}).get("payload", {}).get("S")
    assert deleted_payload == "hello", (
        f"expected deleted Attributes to echo the item's payload 'hello', got {del_resp}"
    )
    read3 = ddb.get_item(TableName=table_name, Key=real_key, ConsistentRead=True)
    assert "Item" not in read3, f"expected item gone after delete, got {read3}"

    # idempotent repeat on the now-missing real key
    resp3 = ddb.delete_item(TableName=table_name, Key=real_key, ReturnValues="ALL_OLD")
    assert "Attributes" not in resp3, f"expected no Attributes on repeat delete, got {resp3}"
    read4 = ddb.get_item(TableName=table_name, Key=real_key, ConsistentRead=True)
    assert "Item" not in read4, f"expected item to remain absent after repeat delete, got {read4}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
