"""update-item-nested-arithmetic-mixed-clauses-and-if-not-exists-parent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-nested-arithmetic-mixed-clauses-and-if-not-exists-parent"
GROUP = "update-expression"
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


def _n(v):
    return {"N": v}


def _s(v):
    return {"S": v}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SET and ADD on list and map paths apply together in one call, several nested SETs
    addressed with one placeholder per path segment touch only their own leaves, and SET on
    if_not_exists(path, {}) creates an absent parent map a later call sets a leaf under.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-nestarith-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    key = {"pk": _s("doc")}
    ddb.put_item(TableName=table, Item={
        **key,
        "a": {"L": [_n("10"), _n("20"), _n("30")]},
        "info": {"M": {"visits": _n("100")}},
    })

    def update(expr, values, rv, names=None):
        kwargs = {"ExpressionAttributeNames": names} if names else {}
        return ddb.update_item(TableName=table, Key=key, UpdateExpression=expr,
                               ExpressionAttributeValues=values, ReturnValues=rv,
                               **kwargs)["Attributes"]

    def read():
        return ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]

    # SET on a list index evaluates a parenthesised arithmetic operand: a[0] = (a[0] + :x)
    # with a[0]=10, :x=5 computes to 15.
    got = update("SET a[0] = (a[0] + :x)", {":x": _n("5")}, "UPDATED_NEW")
    want = {"a": {"L": [_n("15")]}}
    assert got == want, f"SET a[0] = (a[0] + :x) with UPDATED_NEW returned {got!r}, expected {want!r}"
    item = read()
    assert item["a"] == {"L": [_n("15"), _n("20"), _n("30")]}, (
        f"after SET a[0] = (a[0] + :x) the list is {item.get('a')!r}"
    )
    assert item["info"] == {"M": {"visits": _n("100")}}, f"info must be untouched: {item.get('info')!r}"

    # SET on a list index and ADD on a map path apply together inside one UpdateExpression;
    # UPDATED_NEW lists only the two touched leaves.
    got = update("SET a[1] = a[1] + :inc ADD info.visits :one",
                 {":inc": _n("5"), ":one": _n("1")}, "UPDATED_NEW")
    want = {"a": {"L": [_n("25")]}, "info": {"M": {"visits": _n("101")}}}
    assert got == want, (
        f"SET a[1] = a[1] + :inc ADD info.visits :one with UPDATED_NEW returned {got!r}, expected {want!r}"
    )
    item = read()
    assert item["a"] == {"L": [_n("15"), _n("25"), _n("30")]}, (
        f"after the mixed SET/ADD call the list is {item.get('a')!r}"
    )
    assert item["info"] == {"M": {"visits": _n("101")}}, (
        f"after the mixed SET/ADD call info is {item.get('info')!r}"
    )

    # Two nested SETs in one call, each addressed with its own placeholder per path segment
    # (#i for the shared parent, #r and #p for each leaf): only the two new leaves are returned.
    got = update(
        "SET #i.#r = :r, #i.#p = :p", {":r": _n("4.5"), ":p": _s("A quiet thriller.")},
        "UPDATED_NEW", names={"#i": "info", "#r": "rating", "#p": "plot"},
    )
    want = {"info": {"M": {"rating": _n("4.5"), "plot": _s("A quiet thriller.")}}}
    assert got == want, f"SET #i.#r = :r, #i.#p = :p with UPDATED_NEW returned {got!r}, expected {want!r}"
    item = read()
    assert item["info"] == {"M": {"visits": _n("101"), "rating": _n("4.5"), "plot": _s("A quiet thriller.")}}, (
        f"after the two per-segment-aliased nested SETs info is {item.get('info')!r}"
    )

    # SET meta = if_not_exists(meta, :empty) creates the absent top-level map "meta".
    got = update("SET meta = if_not_exists(meta, :empty)", {":empty": {"M": {}}}, "UPDATED_NEW")
    want = {"meta": {"M": {}}}
    assert got == want, f"SET meta = if_not_exists(meta, :empty) with UPDATED_NEW returned {got!r}, expected {want!r}"
    item = read()
    assert item["meta"] == {"M": {}}, f"after creating the parent map, meta is {item.get('meta')!r}"

    # A later call sets a nested leaf under the map the previous call created.
    got = update("SET meta.flag = :v", {":v": {"BOOL": True}}, "UPDATED_NEW")
    want = {"meta": {"M": {"flag": {"BOOL": True}}}}
    assert got == want, f"SET meta.flag = :v with UPDATED_NEW returned {got!r}, expected {want!r}"

    final = read()
    expected_final = {
        **key,
        "a": {"L": [_n("15"), _n("25"), _n("30")]},
        "info": {"M": {"visits": _n("101"), "rating": _n("4.5"), "plot": _s("A quiet thriller.")}},
        "meta": {"M": {"flag": {"BOOL": True}}},
    }
    assert final == expected_final, f"final item is {final!r}, expected {expected_final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
