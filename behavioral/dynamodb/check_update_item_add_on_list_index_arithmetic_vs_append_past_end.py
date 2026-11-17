"""update-item-add-on-list-index-arithmetic-vs-append-past-end."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-add-on-list-index-arithmetic-vs-append-past-end"
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
    """ADD on an in-bounds numeric list index performs arithmetic on the existing element;
    ADD on a list index past the end has no element to add to, so it appends the raw operand,
    of any type, at the end instead.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-addidx-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    def update(pk, expr, values, rv):
        key = {"pk": _s(pk)}
        return ddb.update_item(TableName=table, Key=key, UpdateExpression=expr,
                               ExpressionAttributeValues=values, ReturnValues=rv)["Attributes"]

    def read(pk):
        return ddb.get_item(TableName=table, Key={"pk": _s(pk)}, ConsistentRead=True)["Item"]

    # ADD on an in-bounds numeric list index adds the operand to the existing element.
    ddb.put_item(TableName=table, Item={"pk": _s("arith"), "a": {"L": [_n("10"), _n("20"), _n("30")]}})
    got = update("arith", "ADD a[0] :v", {":v": _n("5")}, "ALL_NEW")
    want = {"pk": _s("arith"), "a": {"L": [_n("15"), _n("20"), _n("30")]}}
    assert got == want, f"ADD a[0] :v on an in-bounds numeric element returned {got!r}, expected {want!r}"
    item = read("arith")
    assert item == want, f"stored item after ADD a[0] :v is {item!r}, expected {want!r}"

    # ADD on a list index past the end has nothing to add to: the numeric operand is appended
    # as a new element, not summed with anything.
    ddb.put_item(TableName=table, Item={"pk": _s("append-n"), "a": {"L": [_n("10"), _n("20"), _n("30")]}})
    got = update("append-n", "ADD a[99] :v", {":v": _n("5")}, "ALL_NEW")
    want = {"pk": _s("append-n"), "a": {"L": [_n("10"), _n("20"), _n("30"), _n("5")]}}
    assert got == want, f"ADD a[99] :v past the end returned {got!r}, expected {want!r}"
    item = read("append-n")
    assert item == want, f"stored item after ADD a[99] :v is {item!r}, expected {want!r}"

    # The same past-the-end ADD appends a Set-typed operand just as readily: nothing at that
    # slot forces the operand to match the list's existing element type.
    ddb.put_item(TableName=table, Item={"pk": _s("append-ss"), "a": {"L": [_n("10")]}})
    got = update("append-ss", "ADD a[9] :v", {":v": {"SS": ["x"]}}, "ALL_NEW")
    want = {"pk": _s("append-ss"), "a": {"L": [_n("10"), {"SS": ["x"]}]}}
    assert got == want, f"ADD a[9] :v with a Set operand past the end returned {got!r}, expected {want!r}"
    item = read("append-ss")
    assert item == want, f"stored item after ADD a[9] :v (Set operand) is {item!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
