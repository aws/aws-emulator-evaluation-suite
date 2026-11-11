"""concurrent-disjoint-nested-map-sets-all-land."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-disjoint-nested-map-sets-all-land"
GROUP = "updates"
SERVICES = ["dynamodb"]

_WRITERS = 50


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


def _create_table(ctx, ddb, prefix, range_type=None):
    """Create an on-demand table keyed pk (S), plus sk of range_type when given; wait ACTIVE."""
    table = ctx.unique_name(prefix)
    keys = [{"AttributeName": "pk", "KeyType": "HASH"}]
    attrs = [{"AttributeName": "pk", "AttributeType": "S"}]
    if range_type:
        keys.append({"AttributeName": "sk", "KeyType": "RANGE"})
        attrs.append({"AttributeName": "sk", "AttributeType": range_type})
    ddb.create_table(
        TableName=table, KeySchema=keys, AttributeDefinitions=attrs, BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    return table


def _get(ddb, table, key):
    """The item at key read with ConsistentRead, or None."""
    return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent UpdateItem calls that each SET a distinct key of one map attribute all succeed,
    and the map then holds every key with its value and the item's other attributes intact.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.UpdateExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb, "sim2real-behav-ddb-nested-")
    key = {"pk": {"S": "doc"}}
    ddb.put_item(TableName=table, Item={**key, "d": {"M": {}}, "keep": {"S": "same"}})

    def write(i):
        """SET d.k<i> = v<i>; return None or the error it raised."""
        try:
            ddb.update_item(
                TableName=table, Key=key, UpdateExpression="SET #d.#t = :v",
                ExpressionAttributeNames={"#d": "d", "#t": f"k{i:02d}"},
                ExpressionAttributeValues={":v": {"S": f"v{i:02d}"}},
            )
            return None
        except ClientError as exc:
            return f"k{i:02d}: {exc.response['Error'].get('Code')}: {exc.response['Error'].get('Message')!r}"

    with ThreadPoolExecutor(max_workers=16) as pool:
        errors = [e for e in pool.map(write, range(_WRITERS)) if e is not None]
    assert errors == [], f"concurrent nested SETs failed: {errors!r}"

    item = _get(ddb, table, key)
    expected = {f"k{i:02d}": {"S": f"v{i:02d}"} for i in range(_WRITERS)}
    got = item["d"]["M"]
    missing = sorted(set(expected) - set(got))
    assert missing == [], f"{len(missing)!r} nested SETs were lost: {missing!r}"
    assert got == expected, f"the map holds {got!r}, expected {expected!r}"
    assert item["keep"] == {"S": "same"}, f"an unrelated attribute changed to {item['keep']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
