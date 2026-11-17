"""set-arithmetic-missing-operand-on-absent-item-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-arithmetic-missing-operand-on-absent-item-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0

_MISSING_ATTR = "The provided expression refers to an attribute that does not exist in the item"


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
            raise RuntimeError(
                f"dynamodb table {table_name!r} could not be deleted: {code}"
            ) from exc


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
    """`SET c = c + :one` against a key that holds no item raises ValidationException with the
    exact missing-attribute message and upserts nothing, while the if_not_exists form creates it.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "ghost-row"}}

    pre = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)
    assert "Item" not in pre, f"the key already holds {pre.get('Item')!r} before any write"

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET c = c + :one",
        ExpressionAttributeValues={":one": {"N": "1"}},
    ))
    assert code == "ValidationException", (
        f"SET c = c + :one against an absent item answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == _MISSING_ATTR, (
        f"the refusal's message is {message!r}; expected {_MISSING_ATTR!r}"
    )

    after_refusal = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)
    assert "Item" not in after_refusal, (
        f"after the refused SET on an absent item, GetItem returned {after_refusal.get('Item')!r}; "
        f"a refused UpdateItem must not upsert the key"
    )

    # Positive control: the guarded form upserts the key and initialises c.
    created = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET c = if_not_exists(c, :zero) + :one",
        ExpressionAttributeValues={":one": {"N": "1"}, ":zero": {"N": "0"}},
        ReturnValues="UPDATED_NEW",
    )["Attributes"]
    assert created == {"c": {"N": "1"}}, (
        f"if_not_exists(c, :zero) + :one on an absent item returned {created!r}, expected c=1"
    )
    stored = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert stored == {**key, "c": {"N": "1"}}, (
        f"after the upsert the item is {stored!r}, expected {{**key, 'c': 1}}"
    )

    # ...and the previously refused expression now succeeds, since c exists.
    second = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET c = c + :one",
        ExpressionAttributeValues={":one": {"N": "1"}}, ReturnValues="UPDATED_NEW",
    )["Attributes"]
    assert second == {"c": {"N": "2"}}, (
        f"SET c = c + :one with c=1 stored returned {second!r}, expected c=2"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
