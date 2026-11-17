"""update-set-copies-missing-attribute-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-set-copies-missing-attribute-rejected"
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


_MISSING_ATTR = "The provided expression refers to an attribute that does not exist in the item"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A SET that copies one attribute's value into another (`SET c2 = b`, no function or
    arithmetic) raises ValidationException naming the missing operand when `b` is absent, and
    writes nothing; the identical expression succeeds once `b` holds a value."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "doc"}}
    original = {**key, "keep": {"S": "k"}}
    ddb.put_item(TableName=table, Item=original)

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET c2 = b",
    ))
    assert code == "ValidationException", (
        f"SET c2 = b with no stored b answered {code!r} ({message!r}), expected ValidationException"
    )
    assert message == _MISSING_ATTR, (
        f"SET c2 = b refusal message is {message!r}, expected {_MISSING_ATTR!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, (
        f"after the refused copy the item is {unchanged!r}, expected it unchanged from {original!r}"
    )
    assert "c2" not in unchanged, (
        f"a refused SET c2 = b must not create the target attribute c2: {unchanged!r}"
    )

    # Positive control: once b holds a value, the identical copy expression succeeds.
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET b = :v",
        ExpressionAttributeValues={":v": {"N": "7"}},
    )
    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET c2 = b", ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"c2": {"N": "7"}}, (
        f"SET c2 = b once b=7 returned {resp['Attributes']!r}, expected c2=7"
    )
    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert final == {**key, "keep": {"S": "k"}, "b": {"N": "7"}, "c2": {"N": "7"}}, (
        f"final item is {final!r}, expected keep intact, b=7 and c2=7"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
