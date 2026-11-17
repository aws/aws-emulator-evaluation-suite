"""update-item-add-list-index-type-mismatch-and-missing-attribute-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-add-list-index-type-mismatch-and-missing-attribute-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_ERR_VALIDATION = "ValidationException"
_MSG_TYPE_MISMATCH = "An operand in the update expression has an incorrect data type"
_MSG_PATH_INVALID = "The document path provided in the update expression is invalid for update"


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


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """ADD on an in-bounds list index with a wrong-type operand, and ADD through a list index
    whose top-level attribute is absent, both reject with ValidationException and leave the
    item unchanged, while the matching-type and existing-attribute forms succeed.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-addrej-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    # ADD a Set operand onto an in-bounds Number list element.
    key_n = {"pk": _s("num-elem")}
    original_n = {**key_n, "a": {"L": [_n("1"), _n("2")]}}
    ddb.put_item(TableName=table, Item=original_n)
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key_n, UpdateExpression="ADD a[0] :v",
        ExpressionAttributeValues={":v": {"SS": ["x"]}},
    ))
    assert code == _ERR_VALIDATION, (
        f"ADD a[0] :v with a Set operand on a Number element answered {code!r} ({message!r}), "
        f"expected {_ERR_VALIDATION}"
    )
    assert message == _MSG_TYPE_MISMATCH, f"the refusal's message is {message!r}, expected {_MSG_TYPE_MISMATCH!r}"
    after = ddb.get_item(TableName=table, Key=key_n, ConsistentRead=True)["Item"]
    assert after == original_n, f"after the refused ADD the item is {after!r}, expected it unchanged: {original_n!r}"

    # ADD a Number operand onto an in-bounds String list element: the mismatch runs the other
    # direction and answers with the same code and message.
    key_s = {"pk": _s("str-elem")}
    original_s = {**key_s, "a": {"L": [_s("x"), _n("2")]}}
    ddb.put_item(TableName=table, Item=original_s)
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key_s, UpdateExpression="ADD a[0] :v",
        ExpressionAttributeValues={":v": _n("5")},
    ))
    assert code == _ERR_VALIDATION, (
        f"ADD a[0] :v with a Number operand on a String element answered {code!r} ({message!r}), "
        f"expected {_ERR_VALIDATION}"
    )
    assert message == _MSG_TYPE_MISMATCH, f"the refusal's message is {message!r}, expected {_MSG_TYPE_MISMATCH!r}"
    after = ddb.get_item(TableName=table, Key=key_s, ConsistentRead=True)["Item"]
    assert after == original_s, f"after the refused ADD the item is {after!r}, expected it unchanged: {original_s!r}"

    # ADD through a list index whose top-level attribute is entirely absent (not merely a
    # wrong-shape parent): the whole document path is invalid for update.
    key_missing = {"pk": _s("missing-attr")}
    original_missing = dict(key_missing)
    ddb.put_item(TableName=table, Item=original_missing)
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key_missing, UpdateExpression="ADD b[5] :v",
        ExpressionAttributeValues={":v": _n("1")},
    ))
    assert code == _ERR_VALIDATION, (
        f"ADD b[5] :v on an absent top-level attribute answered {code!r} ({message!r}), expected "
        f"{_ERR_VALIDATION}"
    )
    assert message == _MSG_PATH_INVALID, f"the refusal's message is {message!r}, expected {_MSG_PATH_INVALID!r}"
    after = ddb.get_item(TableName=table, Key=key_missing, ConsistentRead=True)["Item"]
    assert after == original_missing, (
        f"after the refused ADD the item is {after!r}, expected it unchanged: {original_missing!r}"
    )

    # Positive controls: the same shapes succeed when the type matches and the attribute exists.
    got = ddb.update_item(
        TableName=table, Key=key_n, UpdateExpression="ADD a[0] :v",
        ExpressionAttributeValues={":v": _n("5")}, ReturnValues="ALL_NEW",
    )["Attributes"]
    assert got == {**key_n, "a": {"L": [_n("6"), _n("2")]}}, (
        f"matching-type ADD a[0] :v returned {got!r}, expected a[0] to become 6"
    )

    got = ddb.update_item(
        TableName=table, Key=key_missing, UpdateExpression="SET a = :empty",
        ExpressionAttributeValues={":empty": {"L": []}}, ReturnValues="ALL_NEW",
    )["Attributes"]
    assert got == {**key_missing, "a": {"L": []}}, f"seeding an empty list for 'a' returned {got!r}"
    got = ddb.update_item(
        TableName=table, Key=key_missing, UpdateExpression="ADD a[9] :v",
        ExpressionAttributeValues={":v": _n("1")}, ReturnValues="ALL_NEW",
    )["Attributes"]
    assert got == {**key_missing, "a": {"L": [_n("1")]}}, (
        f"ADD a[9] :v once 'a' exists returned {got!r}, expected the operand appended"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
