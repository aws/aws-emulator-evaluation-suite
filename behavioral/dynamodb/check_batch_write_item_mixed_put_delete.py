"""batch-write-item-mixed-put-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-mixed-put-delete"
GROUP = 'batch'
SERVICES = ['dynamodb']

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


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
        Tags=_TAGS_KV,
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_for_table_active(ddb, table_name)
    return table_name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single BatchWriteItem call can Put a new item and Delete an existing item across requests atomically per-entry."""
    ddb = ctx.client("dynamodb")
    table_name = _create_simple_table(ddb, ctx)
    keep_key = {"pk": {"S": "batch-keep"}, "sk": {"S": "a"}}
    del_key = {"pk": {"S": "batch-del"}, "sk": {"S": "a"}}
    ddb.put_item(TableName=table_name, Item=dict(del_key))

    resp = ddb.batch_write_item(
        RequestItems={
            table_name: [
                {"PutRequest": {"Item": {**keep_key, "v": {"S": "new"}}}},
                {"DeleteRequest": {"Key": del_key}},
            ]
        }
    )
    unprocessed = resp.get("UnprocessedItems", {})
    assert unprocessed == {}, f"expected no unprocessed items, got {unprocessed!r}"

    got_keep = ddb.get_item(TableName=table_name, Key=keep_key, ConsistentRead=True)
    assert got_keep["Item"]["v"] == {"S": "new"}, (
        f"expected PutRequest item v='new', got {got_keep.get('Item')!r}"
    )
    got_del = ddb.get_item(TableName=table_name, Key=del_key, ConsistentRead=True)
    assert "Item" not in got_del, (
        f"expected DeleteRequest item to be gone, still present: {got_del.get('Item')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
