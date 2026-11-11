"""projection-overlap-path-order-and-list-index-rendering-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "projection-overlap-path-order-and-list-index-rendering-rejected"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_OVERLAP = (
    "Invalid ProjectionExpression: Two document paths overlap with each other; "
    "must remove or rewrite one of these paths; path one: {one}, path two: {two}"
)


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ProjectionExpression overlap names path one/two in expression order (child first, the first
    overlapping pair after an unrelated path, a list index as [l, [0]]) on GetItem and Scan.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ProjectionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-projovl-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    item = {
        "pk": {"S": "k1"},
        "x": {"S": "vx"},
        "a": {"M": {"b": {"S": "vb"}, "c": {"S": "vc"}}},
        "alist": {"L": [{"S": "l0"}, {"S": "l1"}]},
    }
    ddb.put_item(TableName=table, Item=item)
    key = {"pk": {"S": "k1"}}

    # Positive control: the same paths without an overlap are served.
    ok = ddb.get_item(
        TableName=table, Key=key, ConsistentRead=True, ProjectionExpression="x, a.b, alist[0]",
    ).get("Item")
    want = {"x": {"S": "vx"}, "a": {"M": {"b": {"S": "vb"}}}, "alist": {"L": [{"S": "l0"}]}}
    assert ok == want, f"GetItem 'x, a.b, alist[0]' returned {ok!r}, expected {want!r}"

    cases = [
        ("a.b, a", _OVERLAP.format(one="[a, b]", two="[a]")),
        ("x, a.b, a", _OVERLAP.format(one="[a, b]", two="[a]")),
        ("alist[0], alist", _OVERLAP.format(one="[alist, [0]]", two="[alist]")),
    ]
    for expr, expected in cases:
        code, msg = _error(lambda expr=expr: ddb.get_item(
            TableName=table, Key=key, ConsistentRead=True, ProjectionExpression=expr,
        ))
        assert (code, msg) == ("ValidationException", expected), (
            f"GetItem ProjectionExpression {expr!r} gave {code!r}: {msg!r}, expected {expected!r}"
        )

    scan_expected = _OVERLAP.format(one="[a]", two="[a, b]")
    code, msg = _error(lambda: ddb.scan(TableName=table, ConsistentRead=True, ProjectionExpression="a, a.b"))
    assert (code, msg) == ("ValidationException", scan_expected), (
        f"Scan ProjectionExpression 'a, a.b' gave {code!r}: {msg!r}, expected {scan_expected!r}"
    )

    scan_ok = ddb.scan(TableName=table, ConsistentRead=True, ProjectionExpression="a.c")["Items"]
    assert scan_ok == [{"a": {"M": {"c": {"S": "vc"}}}}], f"Scan 'a.c' returned {scan_ok!r}"

    full = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert full == item, f"the item changed across the refused reads: {full!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
