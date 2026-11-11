"""update-item-updated-new-old-rebuild-nested-leaves-only."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-updated-new-old-rebuild-nested-leaves-only"
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


def _s(v):
    return {"S": v}


def _m(**members):
    return {"M": members}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UPDATED_NEW/UPDATED_OLD on nested map and list-index SETs return only the touched leaves
    rebuilt under their parents (siblings omitted, one-element lists), with old or new values.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-rvnest-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    key = {"pk": _s("doc")}
    ddb.put_item(TableName=table, Item={
        **key,
        "a": _m(b=_m(c=_s("c0"), d=_s("d0")), e=_s("e0"), f=_s("f0")),
        "mylist": {"L": [_s("x0"), _s("x1"), _s("x2")]},
        "other": _s("o0"),
    })

    def update(expr, values, rv, names=None):
        kwargs = {"ExpressionAttributeNames": names} if names else {}
        return ddb.update_item(TableName=table, Key=key, UpdateExpression=expr,
                               ExpressionAttributeValues=values, ReturnValues=rv,
                               **kwargs).get("Attributes")

    got = update("SET a.b.c = :v", {":v": _s("c1")}, "UPDATED_NEW")
    want = {"a": _m(b=_m(c=_s("c1")))}
    assert got == want, f"SET a.b.c with UPDATED_NEW returned {got!r}, expected {want!r}"

    got = update("SET a.b.c = :v", {":v": _s("c2")}, "UPDATED_OLD")
    want = {"a": _m(b=_m(c=_s("c1")))}
    assert got == want, f"SET a.b.c with UPDATED_OLD returned {got!r}, expected {want!r}"

    got = update("SET a.b.c = :c, a.e = :e", {":c": _s("c3"), ":e": _s("e1")}, "UPDATED_NEW")
    want = {"a": _m(b=_m(c=_s("c3")), e=_s("e1"))}
    assert got == want, f"SET a.b.c, a.e with UPDATED_NEW returned {got!r}, expected {want!r}"

    got = update("SET #a.#b.#c = :c, #a.#e = :e", {":c": _s("c4"), ":e": _s("e2")}, "UPDATED_OLD",
                 names={"#a": "a", "#b": "b", "#c": "c", "#e": "e"})
    want = {"a": _m(b=_m(c=_s("c3")), e=_s("e1"))}
    assert got == want, f"aliased SET of two sub-paths with UPDATED_OLD returned {got!r}, expected {want!r}"

    got = update("SET mylist[1] = :v", {":v": _s("y1")}, "UPDATED_NEW")
    want = {"mylist": {"L": [_s("y1")]}}
    assert got == want, f"SET mylist[1] with UPDATED_NEW returned {got!r}, expected {want!r}"

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    want = {
        **key,
        "a": _m(b=_m(c=_s("c4"), d=_s("d0")), e=_s("e2"), f=_s("f0")),
        "mylist": {"L": [_s("x0"), _s("y1"), _s("x2")]},
        "other": _s("o0"),
    }
    assert item == want, f"after the nested updates the item is {item!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
