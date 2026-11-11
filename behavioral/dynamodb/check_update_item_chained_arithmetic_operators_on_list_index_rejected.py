"""update-item-chained-arithmetic-operators-on-list-index-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-chained-arithmetic-operators-on-list-index-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_ERR_VALIDATION = "ValidationException"
_MSG_CHAINED_OP = (
    '1 validation error detected: Invalid UpdateExpression: Syntax error; token: "-", near: ") - :y"'
)


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


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if fn() unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call unexpectedly succeeded where an error was required: {resp!r}")


def _n(v):
    return {"N": v}


def _s(v):
    return {"S": v}


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SET operand on a list index chaining two arithmetic operators
    (a[0] + :x) - :y is a ValidationException syntax error and leaves the list unchanged, while
    a single operator wrapped in one set of parentheses on the same index succeeds.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-chainop-")
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
    original = {**key, "a": {"L": [_n("10"), _n("20"), _n("30")]}}
    ddb.put_item(TableName=table, Item=original)

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET a[0] = (a[0] + :x) - :y",
        ExpressionAttributeValues={":x": _n("5"), ":y": _n("3")},
    ))
    assert code == _ERR_VALIDATION, (
        f"SET a[0] = (a[0] + :x) - :y answered {code!r} ({message!r}), expected {_ERR_VALIDATION}"
    )
    assert message == _MSG_CHAINED_OP, f"the refusal's message is {message!r}, expected {_MSG_CHAINED_OP!r}"
    after = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after == original, f"after the refused SET the item is {after!r}, expected it unchanged: {original!r}"

    # Positive control: a single operator wrapped in one set of parentheses on the same
    # list index succeeds.
    got = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET a[0] = (a[0] + :x)",
        ExpressionAttributeValues={":x": _n("5")}, ReturnValues="UPDATED_NEW",
    )["Attributes"]
    assert got == {"a": {"L": [_n("15")]}}, f"SET a[0] = (a[0] + :x) on the same index returned {got!r}"
    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert final == {**key, "a": {"L": [_n("15"), _n("20"), _n("30")]}}, (
        f"final list is {final.get('a')!r}, expected [15, 20, 30]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
