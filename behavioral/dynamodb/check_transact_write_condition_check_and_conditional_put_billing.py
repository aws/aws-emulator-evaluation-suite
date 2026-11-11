"""transact-write-condition-check-and-conditional-put-billing."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-condition-check-and-conditional-put-billing"
GROUP = "transactions"
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


def _create_table(ctx, ddb, prefix):
    """Create an on-demand table keyed pk (S), with no index; wait ACTIVE."""
    table = ctx.unique_name(prefix)
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    return table


def _arm(consumed, table):
    """The single ConsumedCapacity entry for ``table`` in a TransactWriteItems response."""
    matches = [c for c in consumed if c.get("TableName") == table]
    assert len(matches) == 1, f"expected exactly one ConsumedCapacity entry for {table!r}, got {consumed!r}"
    return matches[0]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """In TransactWriteItems a Put whose condition passes costs the same 2 write units as an
    unconditional Put, and a ConditionCheck on its own table bills 2 write units, no read units.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html
    """
    ddb = ctx.client("dynamodb")
    table_check = _create_table(ctx, ddb, "sim2real-behav-ddb-txccb-chk-")
    table_plain = _create_table(ctx, ddb, "sim2real-behav-ddb-txccb-pln-")
    table_cond = _create_table(ctx, ddb, "sim2real-behav-ddb-txccb-cnd-")

    checked_key = {"pk": {"S": "watched"}}
    ddb.put_item(TableName=table_check, Item={**checked_key, "status": {"S": "ok"}})

    resp = ddb.transact_write_items(
        TransactItems=[
            {
                "ConditionCheck": {
                    "TableName": table_check,
                    "Key": checked_key,
                    "ConditionExpression": "#s = :ok",
                    "ExpressionAttributeNames": {"#s": "status"},
                    "ExpressionAttributeValues": {":ok": {"S": "ok"}},
                }
            },
            {"Put": {"TableName": table_plain, "Item": {"pk": {"S": "row"}, "v": {"S": "x"}}}},
            {
                "Put": {
                    "TableName": table_cond,
                    "Item": {"pk": {"S": "row"}, "v": {"S": "x"}},
                    "ConditionExpression": "attribute_not_exists(pk)",
                }
            },
        ],
        ReturnConsumedCapacity="INDEXES",
    )
    consumed = resp["ConsumedCapacity"]
    assert len(consumed) == 3, f"expected one ConsumedCapacity entry per table, got {consumed!r}"

    plain_cap = _arm(consumed, table_plain)
    cond_cap = _arm(consumed, table_cond)
    check_cap = _arm(consumed, table_check)

    assert (plain_cap["CapacityUnits"], plain_cap["WriteCapacityUnits"]) == (2.0, 2.0), (
        f"the unconditional Put consumed {plain_cap!r}, expected 2.0 write units"
    )
    assert "ReadCapacityUnits" not in plain_cap, f"an unconditional Put reported read units: {plain_cap!r}"

    assert (cond_cap["CapacityUnits"], cond_cap["WriteCapacityUnits"]) == (2.0, 2.0), (
        f"the conditional Put consumed {cond_cap!r}, expected the same 2.0 write units as unconditional"
    )
    assert "ReadCapacityUnits" not in cond_cap, f"a passing conditional Put reported read units: {cond_cap!r}"
    cond_billing = {k: v for k, v in cond_cap.items() if k != "TableName"}
    plain_billing = {k: v for k, v in plain_cap.items() if k != "TableName"}
    assert cond_billing == plain_billing, (
        f"a passing condition changed what the Put billed: conditional {cond_billing!r} vs plain {plain_billing!r}"
    )

    assert (check_cap["CapacityUnits"], check_cap["WriteCapacityUnits"]) == (2.0, 2.0), (
        f"the ConditionCheck consumed {check_cap!r}, expected 2.0 write units"
    )
    assert "ReadCapacityUnits" not in check_cap, f"a ConditionCheck reported read units: {check_cap!r}"
    assert check_cap.get("Table") == {"CapacityUnits": 2.0, "WriteCapacityUnits": 2.0}, (
        f"the ConditionCheck's table breakdown was {check_cap.get('Table')!r}"
    )

    plain_item = ddb.get_item(TableName=table_plain, Key={"pk": {"S": "row"}}, ConsistentRead=True).get("Item")
    assert plain_item == {"pk": {"S": "row"}, "v": {"S": "x"}}, f"the unconditional Put stored {plain_item!r}"
    cond_item = ddb.get_item(TableName=table_cond, Key={"pk": {"S": "row"}}, ConsistentRead=True).get("Item")
    assert cond_item == {"pk": {"S": "row"}, "v": {"S": "x"}}, f"the conditional Put stored {cond_item!r}"
    checked_item = ddb.get_item(TableName=table_check, Key=checked_key, ConsistentRead=True).get("Item")
    assert checked_item == {**checked_key, "status": {"S": "ok"}}, (
        f"the ConditionCheck's own item changed to {checked_item!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
