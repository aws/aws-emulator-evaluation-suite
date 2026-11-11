"""item-size-limit-counts-list-element-overhead."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "item-size-limit-counts-list-element-overhead"
GROUP = "validation"
SERVICES = ["dynamodb"]

_TOO_BIG_MESSAGE = "Item size has exceeded the maximum allowed size"


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
    """Poll DescribeTable every 2 s until the table and its indexes are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A 150,000-element list of 2-byte strings (300 KB of values, over 400 KB with element overhead) is
    refused and not stored; a 130,000-element one is stored and bills exactly 381 CapacityUnits.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CapacityUnitCalculations.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-lsize-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    resp = ddb.put_item(
        TableName=table, Item={"pk": {"S": "under"}, "data": {"L": [{"S": "aa"}] * 130_000}},
        ReturnConsumedCapacity="TOTAL",
    )
    cu = resp.get("ConsumedCapacity", {}).get("CapacityUnits")
    assert cu == 381.0, f"the 130,000-element list item consumed {cu!r} CapacityUnits, expected 381.0"
    stored = ddb.get_item(TableName=table, Key={"pk": {"S": "under"}}, ConsistentRead=True).get("Item", {})
    count = len(stored.get("data", {}).get("L", []))
    assert count == 130_000, f"the stored list reads back with {count!r} elements, expected 130000"

    code, msg = _error(lambda: ddb.put_item(
        TableName=table, Item={"pk": {"S": "over"}, "data": {"L": [{"S": "aa"}] * 150_000}}))
    assert (code, msg) == ("ValidationException", _TOO_BIG_MESSAGE), (
        f"the 150,000-element list item gave {code!r}: {msg!r}"
    )
    gone = ddb.get_item(TableName=table, Key={"pk": {"S": "over"}}, ConsistentRead=True)
    assert "Item" not in gone, f"the refused item was stored: {sorted(gone['Item'])!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
