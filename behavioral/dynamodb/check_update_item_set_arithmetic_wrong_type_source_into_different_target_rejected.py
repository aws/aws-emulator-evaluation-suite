"""update-item-set-arithmetic-wrong-type-source-into-different-target-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-set-arithmetic-wrong-type-source-into-different-target-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0

_TYPE_MISMATCH = (
    "ValidationException",
    "An operand in the update expression has an incorrect data type",
)


def _error(fn):
    """(code, message) of the ClientError fn() raises; RAISES if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call unexpectedly SUCCEEDED where an error was required: {resp!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _delete_table_when_possible(ddb, table_name):
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


def _create_table(ctx, ddb):
    name = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_when_possible(ddb, name))
    deadline = time.monotonic() + _TABLE_ACTIVE_BUDGET_S
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return name
        time.sleep(2.0)
    raise AssertionError(f"table {name!r} not ACTIVE within {_TABLE_ACTIVE_BUDGET_S}s: {status!r}")


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """SET into an absent target attribute is rejected with ValidationException when the
    arithmetic operand it reads is not a Number, in either operand order, and creates nothing;
    the identical expression succeeds once the operand is a Number.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "item"}}
    original = {**key, "label": {"S": "Jane Doe"}, "price": {"N": "20"}}
    ddb.put_item(TableName=table, Item=original)

    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=key, UpdateExpression="SET derived = label + :tax",
            ExpressionAttributeValues={":tax": {"N": "5"}},
        ),
        *_TYPE_MISMATCH,
    )
    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=key, UpdateExpression="SET derived = :tax + label",
            ExpressionAttributeValues={":tax": {"N": "5"}},
        ),
        *_TYPE_MISMATCH,
    )

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, (
        f"after both refused updates the item is {unchanged!r}, expected it unchanged from "
        f"{original!r} (a target that gets created anyway would add a 'derived' attribute)"
    )

    # Positive control: the identical shape, writing into the same different target, with a
    # Number-typed source instead.
    control = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET derived = price + :tax",
        ExpressionAttributeValues={":tax": {"N": "5"}}, ReturnValues="ALL_NEW",
    )["Attributes"]
    assert control == {**original, "derived": {"N": "25"}}, (
        f"SET derived = price + :tax with price=20, :tax=5 returned ALL_NEW {control!r}, "
        f"expected the original item plus derived=25"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
