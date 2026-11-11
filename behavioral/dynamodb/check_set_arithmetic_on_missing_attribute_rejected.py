"""set-arithmetic-on-missing-attribute-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-arithmetic-on-missing-attribute-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0


def _error(fn):
    """(code, message) of the ClientError fn() raises; RAISES if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call unexpectedly SUCCEEDED where an error was required: {resp!r}")


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
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("ResourceNotFoundException",):
                raise RuntimeError(
                    f"dynamodb table {table_name!r} could not be deleted: {code}"
                ) from exc
            return


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
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """`SET c = c + :one` on an item without `c` raises ValidationException with the exact message and leaves the item
    unchanged, while `SET c = if_not_exists(c, :zero) + :one` sets c to 1 and then to 2.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "counter"}}
    ddb.put_item(TableName=table, Item={**key, "label": {"S": "orig"}})

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET c = c + :one",
        ExpressionAttributeValues={":one": {"N": "1"}},
    ))
    assert code == "ValidationException", (
        f"SET c = c + :one with no stored c answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == "The provided expression refers to an attribute that does not exist in the item", (
        f"the refusal's message is {message!r}; real AWS names the missing operand as an "
        f"attribute that does not exist in the item"
    )

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert item == {**key, "label": {"S": "orig"}}, (
        f"after the refused SET the item is {item!r}; a refused UpdateItem must change nothing "
        f"(a target that treats the missing operand as 0 writes c=1 here)"
    )

    # Positive control: the guarded form initialises the attribute...
    first = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET c = if_not_exists(c, :zero) + :one",
        ExpressionAttributeValues={":one": {"N": "1"}, ":zero": {"N": "0"}},
        ReturnValues="UPDATED_NEW",
    )["Attributes"]
    assert first == {"c": {"N": "1"}}, f"if_not_exists initialised c to {first!r}, expected 1"

    # ...and the refused expression succeeds once c exists.
    second = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET c = c + :one",
        ExpressionAttributeValues={":one": {"N": "1"}}, ReturnValues="UPDATED_NEW",
    )["Attributes"]
    assert second == {"c": {"N": "2"}}, (
        f"SET c = c + :one with c=1 stored returned {second!r}, expected c=2; the refusal above "
        f"must have been about the missing operand, not the expression"
    )
    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert final == {**key, "label": {"S": "orig"}, "c": {"N": "2"}}, (
        f"final item is {final!r}, expected label intact and c=2"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
