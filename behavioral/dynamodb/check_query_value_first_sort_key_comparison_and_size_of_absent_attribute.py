"""query-value-first-sort-key-comparison-and-size-of-absent-attribute."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-value-first-sort-key-comparison-and-size-of-absent-attribute"
GROUP = "query"
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


def _sks(resp):
    return [int(it["sk"]["N"]) for it in resp["Items"]]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A key condition with the value on the left (':lo <= sk', ':hi > sk') selects what the
    sort-key-first form does; size() of an absent attribute matches nothing, size('') matches 0.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Query.KeyConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-qcmp-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "N"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    for i in range(1, 11):
        item = {"pk": {"S": "u"}, "sk": {"N": str(i)}, "tag": {"S": "" if i == 4 else f"t{i}"}}
        ddb.put_item(TableName=table, Item=item)

    def query(kce, values, **extra):
        return ddb.query(
            TableName=table, KeyConditionExpression=kce, ConsistentRead=True,
            ExpressionAttributeValues={":p": {"S": "u"}, **values}, **extra,
        )

    lo = {":lo": {"N": "3"}}
    value_first = query("pk = :p AND :lo <= sk", lo)
    key_first = query("pk = :p AND sk >= :lo", lo)
    assert _sks(value_first) == list(range(3, 11)), f"':lo <= sk' with lo=3 selected {_sks(value_first)!r}"
    assert _sks(value_first) == _sks(key_first), (
        f"':lo <= sk' {_sks(value_first)!r} differs from 'sk >= :lo' {_sks(key_first)!r}"
    )
    hi = query("pk = :p AND :hi > sk", {":hi": {"N": "4"}})
    assert _sks(hi) == [1, 2, 3], f"':hi > sk' with hi=4 selected {_sks(hi)!r}"

    zero = {":zero": {"N": "0"}}
    absent = query("pk = :p", zero, FilterExpression="size(nonexistent_attr) = :zero")
    assert (absent["Count"], absent["ScannedCount"]) == (0, 10), (
        f"size(nonexistent_attr) = 0 must match nothing of 10 items, got {absent!r}"
    )
    empty = query("pk = :p", zero, FilterExpression="size(tag) = :zero")
    assert _sks(empty) == [4], f"size(tag) = 0 must match only the empty-string item 4, got {_sks(empty)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
