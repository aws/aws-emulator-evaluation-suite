"""gsi-four-hash-attribute-key-query-order-free-and-tracks-moves-and-deletes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-four-hash-attribute-key-query-order-free-and-tracks-moves-and-deletes"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_INDEX = "by-four"
_HASH = ["ka", "kb", "kc", "kd"]


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


def _poll(ctx, read, want):
    """read() every 2 s until it equals want, bounded by the run budget."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 120.0) - 20.0)
    while True:
        value = read()
        if value == want or time.monotonic() >= deadline:
            return value
        time.sleep(2)


def _item(pk, values, extra):
    item = {"pk": {"S": pk}, "data": {"S": extra}}
    item.update({name: {"S": v} for name, v in zip(_HASH, values)})
    return item


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI keyed on four HASH attributes is created; a Query naming them in any order finds the item,
    an overwrite changing the key moves it to the new composite partition, and a delete removes it.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GSI.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-gsi4-")
    key_schema = [{"AttributeName": n, "KeyType": "HASH"} for n in _HASH]
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ["pk", *_HASH]],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[{"IndexName": _INDEX, "KeySchema": key_schema, "Projection": {"ProjectionType": "ALL"}}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    desc = _wait_active(ddb, ctx, table)
    described = [g["KeySchema"] for g in desc["GlobalSecondaryIndexes"]]
    assert described == [key_schema], f"the four-HASH GSI describes its key as {described!r}"

    def query(values, order):
        names = {f"#{n}": n for n in _HASH}
        vals = {f":{n}": {"S": v} for n, v in zip(_HASH, values)}
        cond = " AND ".join(f"#{n} = :{n}" for n in order)
        items = []
        for page in ddb.get_paginator("query").paginate(
            TableName=table, IndexName=_INDEX, KeyConditionExpression=cond,
            ExpressionAttributeNames=names, ExpressionAttributeValues=vals,
        ):
            items.extend(page["Items"])
        return sorted((i["pk"]["S"], i["data"]["S"]) for i in items)

    old = ["t1", "eu", "web", "blue"]
    new = ["t2", "us", "api", "red"]
    other = ["t1", "eu", "web", "green"]
    ddb.put_item(TableName=table, Item=_item("p1", old, "first"))
    ddb.put_item(TableName=table, Item=_item("p2", other, "sibling"))

    got = _poll(ctx, lambda: query(old, _HASH), [("p1", "first")])
    assert got == [("p1", "first")], f"the four-attribute key in schema order selected {got!r}"
    reversed_order = list(reversed(_HASH))
    got = _poll(ctx, lambda: query(old, reversed_order), [("p1", "first")])
    assert got == [("p1", "first")], f"the same key named in order {reversed_order!r} selected {got!r}"
    got = _poll(ctx, lambda: query(other, ["kc", "ka", "kd", "kb"]), [("p2", "sibling")])
    assert got == [("p2", "sibling")], f"the sibling key differing only in kd selected {got!r}"

    ddb.put_item(TableName=table, Item=_item("p1", new, "moved"))
    got = _poll(ctx, lambda: query(new, reversed_order), [("p1", "moved")])
    assert got == [("p1", "moved")], f"after the overwrite the new composite key selected {got!r}"
    got = _poll(ctx, lambda: query(old, _HASH), [])
    assert got == [], f"after the overwrite the old composite key still selects {got!r}"

    ddb.delete_item(TableName=table, Key={"pk": {"S": "p1"}})
    got = _poll(ctx, lambda: query(new, _HASH), [])
    assert got == [], f"after DeleteItem the index still holds {got!r}"
    got = query(other, _HASH)
    assert got == [("p2", "sibling")], f"after deleting p1 the sibling key selected {got!r}"
    base = ddb.get_item(TableName=table, Key={"pk": {"S": "p1"}}, ConsistentRead=True)
    assert "Item" not in base, f"the deleted item still reads back: {base.get('Item')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
