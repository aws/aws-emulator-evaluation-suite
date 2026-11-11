"""projection-list-index-out-of-range-null-element-and-nested-list."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "projection-list-index-out-of-range-null-element-and-nested-list"
GROUP = "projection"
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


_NULL = {"NULL": True}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetItem projection drops an out-of-range list index, keeps a NULL list element in place or
    by index, and compacts a list nested under a list element's map to the selected element.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ProjectionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-projlist-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    key = {"pk": _s("doc")}
    item = {
        **key,
        "mylist": {"L": [_s("zero"), _s("one")]},
        "listWithNull": {"L": [_s("keep0"), _NULL, _s("keep2")]},
        "nestedList": {"L": [
            {"M": {"inner": {"L": [_s("i0"), _s("i1"), _s("i2")]}, "other": _s("o")}},
            {"M": {"inner": {"L": [_s("j0")]}}},
        ]},
    }
    ddb.put_item(TableName=table, Item=item)

    def project(expr, names=None):
        kwargs = {"ExpressionAttributeNames": names} if names else {}
        return ddb.get_item(TableName=table, Key=key, ConsistentRead=True,
                            ProjectionExpression=expr, **kwargs).get("Item")

    cases = [
        ("mylist[99]", None, {}),
        ("pk, mylist[99], mylist[1]", None, {**key, "mylist": {"L": [_s("one")]}}),
        ("listWithNull", None, {"listWithNull": item["listWithNull"]}),
        ("listWithNull[1]", None, {"listWithNull": {"L": [_NULL]}}),
        ("listWithNull[0], listWithNull[2]", None, {"listWithNull": {"L": [_s("keep0"), _s("keep2")]}}),
        ("nestedList[0].#i[1]", {"#i": "inner"},
         {"nestedList": {"L": [{"M": {"inner": {"L": [_s("i1")]}}}]}}),
    ]
    for expr, names, want in cases:
        got = project(expr, names)
        assert got == want, f"ProjectionExpression {expr!r} returned {got!r}, expected {want!r}"

    whole = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert whole == item, f"the unprojected item read back as {whole!r}, expected {item!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
