"""write-capacity-counts-list-and-map-element-overhead."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "write-capacity-counts-list-and-map-element-overhead"
GROUP = "capacity"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem and UpdateItem bill list- and map-heavy items by their size with per-element, per-entry
    and container overhead: exact CapacityUnits 2/5/9 for dense lists, 5, 4 and 5 for nested shapes.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CapacityUnitCalculations.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-lmcu-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    cases = [
        ("scalar", {"n": {"N": "1"}, "s": {"S": "hello"}}, 1.0),
        ("l500", {"data": {"L": [{"S": "aa"}] * 500}}, 2.0),
        ("l1500", {"data": {"L": [{"S": "aa"}] * 1500}}, 5.0),
        ("l3000", {"data": {"L": [{"S": "aa"}] * 3000}}, 9.0),
        ("m800", {"data": {"M": {f"k{i}": {"S": "v"} for i in range(800)}}}, 5.0),
        ("lofm", {"data": {"L": [{"M": {"a": {"S": "b"}}} for _ in range(500)]}}, 4.0),
        ("mofl", {"data": {"M": {f"k{i}": {"L": [{"S": "b"}]} for i in range(500)}}}, 5.0),
    ]
    for pk, attrs, want in cases:
        resp = ddb.put_item(TableName=table, Item={"pk": {"S": pk}, **attrs}, ReturnConsumedCapacity="TOTAL")
        cu = resp.get("ConsumedCapacity", {}).get("CapacityUnits")
        assert cu == want, f"PutItem of {pk!r} consumed {cu!r} CapacityUnits, expected {want!r}"

    resp = ddb.update_item(
        TableName=table, Key={"pk": {"S": "upd"}}, UpdateExpression="SET #d = :v",
        ExpressionAttributeNames={"#d": "data"},
        ExpressionAttributeValues={":v": {"L": [{"S": "aa"}] * 1500}},
        ReturnConsumedCapacity="TOTAL",
    )
    cu = resp.get("ConsumedCapacity", {}).get("CapacityUnits")
    assert cu == 5.0, f"UpdateItem SET of a 1500-element list consumed {cu!r} CapacityUnits, expected 5.0"

    stored = ddb.get_item(TableName=table, Key={"pk": {"S": "upd"}}, ConsistentRead=True).get("Item", {})
    count = len(stored.get("data", {}).get("L", []))
    assert count == 1500, f"the updated item reads back a list of {count!r} elements, expected 1500"
    stored = ddb.get_item(TableName=table, Key={"pk": {"S": "m800"}}, ConsistentRead=True).get("Item", {})
    count = len(stored.get("data", {}).get("M", {}))
    assert count == 800, f"the 800-entry map reads back with {count!r} entries"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
