"""batch-write-item-multi-table-put-and-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-multi-table-put-and-delete"
GROUP = "batch"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_for_table_active(ddb, table_name, timeout_s=90.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never went ACTIVE in {timeout_s}s (last={status})")


def _simple_table(ctx, ddb, prefix):
    name = ctx.unique_name(prefix)
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda n=name: ddb.delete_table(TableName=n), "ResourceNotFoundException"))
    _wait_for_table_active(ddb, name)
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single BatchWriteItem spanning two tables -- a put into one, a delete from the other --
    applies both writes and returns an empty UnprocessedItems.
    """
    ddb = ctx.client("dynamodb")
    table_a = _simple_table(ctx, ddb, "sim2real-behav-bwi-a-")
    table_b = _simple_table(ctx, ddb, "sim2real-behav-bwi-b-")

    keep_key = {"pk": {"S": "keep"}}
    del_key = {"pk": {"S": "del"}}
    ddb.put_item(TableName=table_b, Item=dict(keep_key))
    ddb.put_item(TableName=table_b, Item=dict(del_key))

    resp = ddb.batch_write_item(
        RequestItems={
            table_a: [{"PutRequest": {"Item": {"pk": {"S": "new"}, "from": {"S": "a"}}}}],
            table_b: [{"DeleteRequest": {"Key": dict(del_key)}}],
        }
    )
    assert resp.get("UnprocessedItems", {}) == {}, (
        f"a batch within limits must leave nothing unprocessed, got {resp.get('UnprocessedItems')!r}"
    )

    put_item = ddb.get_item(TableName=table_a, Key={"pk": {"S": "new"}}, ConsistentRead=True).get("Item")
    assert put_item == {"pk": {"S": "new"}, "from": {"S": "a"}}, (
        f"the put into table_a did not land, got {put_item!r}"
    )
    deleted = ddb.get_item(TableName=table_b, Key=del_key, ConsistentRead=True)
    assert "Item" not in deleted, f"the deleted key is still present in table_b: {deleted.get('Item')!r}"
    kept = ddb.get_item(TableName=table_b, Key=keep_key, ConsistentRead=True).get("Item")
    assert kept == keep_key, f"an untouched key in table_b must survive the batch, got {kept!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
