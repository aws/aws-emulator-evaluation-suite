"""update-item-without-actions-upserts-key-only-item."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-without-actions-upserts-key-only-item"
GROUP = "update-expression"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _get(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem with only a Key and no update actions creates a key-only item for a new key,
    leaves an existing item unchanged, and returns no Attributes in either case.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-noact-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    assert _get(ddb, table, "fresh") is None, "the new key already holds an item before the update"
    resp = ddb.update_item(TableName=table, Key={"pk": {"S": "fresh"}})
    assert "Attributes" not in resp, f"action-free UpdateItem on a new key returned {resp.get('Attributes')!r}"
    created = _get(ddb, table, "fresh")
    assert created == {"pk": {"S": "fresh"}}, (
        f"action-free UpdateItem on a new key must create a key-only item, got {created!r}"
    )

    seeded = {"pk": {"S": "existing"}, "v": {"S": "keep"}, "n": {"N": "7"}}
    ddb.put_item(TableName=table, Item=seeded)
    resp = ddb.update_item(TableName=table, Key={"pk": {"S": "existing"}})
    assert "Attributes" not in resp, (
        f"action-free UpdateItem on an existing item returned {resp.get('Attributes')!r}"
    )
    after = _get(ddb, table, "existing")
    assert after == seeded, f"action-free UpdateItem changed the existing item to {after!r}"

    count = ddb.scan(TableName=table, Select="COUNT", ConsistentRead=True)["Count"]
    assert count == 2, f"expected exactly the two items, the table holds {count!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
