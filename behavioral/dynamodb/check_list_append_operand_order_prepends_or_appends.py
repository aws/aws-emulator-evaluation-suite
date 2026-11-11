"""list-append-operand-order-prepends-or-appends."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-append-operand-order-prepends-or-appends"
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


def _strings(attr):
    return [e["S"] for e in attr["L"]]


@tags(
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "axis:happy-path",
    "cap:c1",
)
def run(ctx) -> None:
    """`list_append(a, b)` concatenates in operand order: `list_append(:new, l)` prepends and
    `list_append(l, :new)` appends; a non-list operand fails with ValidationException and leaves
    the stored list unchanged."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "concat"}}
    ddb.put_item(TableName=table, Item={**key, "l": {"L": [{"S": "b"}, {"S": "c"}]}})

    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET l = list_append(:new, l)",
        ExpressionAttributeValues={":new": {"L": [{"S": "a0"}, {"S": "a1"}]}},
        ReturnValues="UPDATED_NEW",
    )
    assert _strings(resp["Attributes"]["l"]) == ["a0", "a1", "b", "c"], (
        f"list_append(:new, l) produced {resp['Attributes']['l']!r}; expected :new PREPENDED in "
        f"its own order"
    )

    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET l = list_append(l, :new)",
        ExpressionAttributeValues={":new": {"L": [{"S": "d"}]}}, ReturnValues="UPDATED_NEW",
    )
    assert _strings(resp["Attributes"]["l"]) == ["a0", "a1", "b", "c", "d"], (
        f"list_append(l, :new) produced {resp['Attributes']['l']!r}; expected :new APPENDED"
    )

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET l = list_append(l, :new)",
        ExpressionAttributeValues={":new": {"S": "not-a-list"}},
    ))
    assert code == "ValidationException", (
        f"list_append with a String operand answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    expected = (
        "1 validation error detected: Invalid UpdateExpression: Incorrect operand type for "
        "operator or function; operator or function: list_append, operand type: S"
    )
    assert message == expected, f"list_append refusal message is {message!r}, expected {expected!r}"
    stored = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]["l"]
    assert _strings(stored) == ["a0", "a1", "b", "c", "d"], (
        f"after the refused list_append the stored list is {stored!r}; a refused update must "
        f"leave the list exactly as the two accepted ones built it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
